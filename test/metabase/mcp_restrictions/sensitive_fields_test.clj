(ns metabase.mcp-restrictions.sensitive-fields-test
  (:require
   [clojure.test :refer :all]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.parameters.field-values :as params.field-values]
   [metabase.query-processor.core :as qp]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :web-server :test-users))

(def ^:private masked mcp-restrictions/masked-value)

;; Fake secrets are assembled at runtime so the source never contains a token-shaped literal, which the pre-commit
;; token scanner and GitHub push protection would both reject.
(def ^:private fake-jwt (str "eyJ" "hbGciOiJIUzI1NiJ9" "." "eyJ" "zdWIiOiIxMjM0NSJ9" "." "c2lnbmF0dXJlLXZhbHVl"))

(def ^:private fake-secrets
  "One fake value per secret shape that [[mcp-restrictions/mask-secret-like-value]] recognizes."
  [fake-jwt
   (str "sk" "-ant-" "abcdefghijklmnopqrstuvwxyz012345")
   (str "sk" "_live_" "abcdefghijklmnopqrstuvwxyz")
   (str "AK" "IA" "IOSFODNN7EXAMPLE")
   (str "gh" "p_" "abcdefghijklmnopqrstuvwxyz0123456789")
   (str "-----BEGIN RSA " "PRIVATE KEY-----\nMIIEow\n-----END RSA " "PRIVATE KEY-----")
   (str "$2b" "$12$" "abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234")])

(defn- run-query [query]
  (mt/rows (qp/process-query query)))

(defmacro ^:private with-mcp-admin
  "Run `body` as an admin with the MCP restrictions enforced and the default sensitive field settings. The test
  database is loaded first: syncing it runs queries that the restrictions would reject."
  [& body]
  `(do
     (mt/id)
     (mt/with-temporary-setting-values [~'mcp-sensitive-fields-auto-detect true
                                        ~'mcp-sensitive-field-ids           []
                                        ~'mcp-non-sensitive-field-ids       []]
       (mt/with-test-user :crowberto
         (mcp-restrictions/with-restrictions-enforced
           ~@body)))))

(deftest sensitive-field-name?-test
  (doseq [field-name ["password" "PASSWORD" "user_password" "client_secret" "access_token" "refreshToken"
                      "api_key" "apiKey" "APIKEY" "private_key" "aws_secret_access_key" "otp" "password_salt"]]
    (is (true? (mcp-restrictions/sensitive-field-name? field-name)) field-name))
  (doseq [field-name ["client_id" "id" "name" "token_type" "token_expires_at" "password_changed_at" "api_key_id"
                      "monkey" "keyboard" "passenger_count" "otp_enabled" "email"]]
    (is (false? (mcp-restrictions/sensitive-field-name? field-name)) field-name)))

(deftest mask-secret-like-value-test
  (doseq [secret fake-secrets]
    (is (= masked (mcp-restrictions/mask-secret-like-value secret)) secret))
  (testing "Only the secret part of a longer string is masked"
    (is (= (str "Bearer " masked " was used")
           (mcp-restrictions/mask-secret-like-value
            (str "Bearer " fake-jwt " was used")))))
  (testing "Ordinary values and non-strings are untouched"
    (doseq [v ["hello world" "client-1234" "2024-01-01" "sk-short" 42 nil]]
      (is (= v (mcp-restrictions/mask-secret-like-value v))))))

(deftest sensitive-fields-test
  (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                     mcp-sensitive-field-ids           [(mt/id :people :email)]
                                     mcp-non-sensitive-field-ids       []]
    (let [by-id (into {} (map (juxt :id :source)) (mcp-restrictions/sensitive-fields (mt/id)))]
      (is (= :detected (by-id (mt/id :people :password))))
      (is (= :manual (by-id (mt/id :people :email))))
      (is (contains? #{:metadata :detected} (by-id (mt/id :users :password))))
      (is (not (contains? by-id (mt/id :people :name))))))
  (testing "Exclusions win over detection"
    (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                       mcp-sensitive-field-ids           []
                                       mcp-non-sensitive-field-ids       [(mt/id :people :password)]]
      (is (not-any? #(= (mt/id :people :password) (:id %)) (mcp-restrictions/sensitive-fields (mt/id))))))
  (testing "Auto-detection can be turned off; fields marked sensitive in the metadata still count"
    (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect false
                                       mcp-sensitive-field-ids           []
                                       mcp-non-sensitive-field-ids       []]
      (is (= #{(mt/id :users :password)}
             (into #{} (map :id) (mcp-restrictions/sensitive-fields (mt/id))))))))

(deftest mbql-masking-test
  (testing "Outside MCP requests values are returned as they are"
    (mt/with-test-user :crowberto
      (is (not= masked (-> (run-query (mt/mbql-query people {:fields [$id $password] :limit 1})) first second)))))
  (with-mcp-admin
    (testing "Selected sensitive fields are masked, other columns are not"
      (let [[[id email password]] (run-query (mt/mbql-query people {:fields   [$id $email $password]
                                                                    :order-by [[:asc $id]]
                                                                    :limit    1}))]
        (is (= 1 id))
        (is (not= masked email))
        (is (= masked password))))
    (testing "Filtering, sorting, grouping or aggregating on a sensitive field is rejected"
      (doseq [query [(mt/mbql-query people {:filter [:starts-with $password "a"]})
                     (mt/mbql-query people {:order-by [[:asc $password]] :limit 1})
                     (mt/mbql-query people {:breakout [$password] :aggregation [[:count]]})
                     (mt/mbql-query people {:aggregation [[:max $password]]})
                     (mt/mbql-query people {:expressions {"p" [:concat $password "x"]}
                                            :fields      [[:expression "p"]]
                                            :limit       1})]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sensitive field"
                              (run-query query)))))
    (testing "Queries that don't touch sensitive fields still work"
      (is (= [[2500]] (run-query (mt/mbql-query people {:aggregation [[:count]]})))))))

(deftest native-query-test
  (with-mcp-admin
    (testing "SQL on a table that holds sensitive fields is rejected, even without naming them"
      (doseq [sql ["SELECT * FROM PEOPLE"
                   "SELECT ID FROM people LIMIT 1"
                   "SELECT row_to_json(p) FROM \"PUBLIC\".\"PEOPLE\" p"
                   "SELECT COUNT(*) FROM ORDERS o JOIN PEOPLE p ON p.ID = o.USER_ID"]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"tables with sensitive fields"
                              (run-query (mt/native-query {:query sql})))
            sql)))
    (testing "SQL on other tables of the same database works"
      (is (= [[18760]] (run-query (mt/native-query {:query "SELECT COUNT(*) FROM ORDERS"})))))
    (testing "Values that look like secrets are masked in any column"
      (is (= [[masked "plain"]]
             (run-query (mt/native-query {:query (str "SELECT '" fake-jwt "' AS X, 'plain' AS Y")})))))))

(deftest field-values-test
  (with-mcp-admin
    (let [field (t2/select-one :model/Field :id (mt/id :people :password))]
      (testing "MCP clients get no values for sensitive fields"
        (is (= [] (:values (params.field-values/get-or-create-field-values! field))))
        (is (not (contains? (params.field-values/field-id->field-values-for-current-user [(:id field)])
                            (:id field)))))))
  (testing "Outside MCP requests field values are unaffected"
    (mt/with-test-user :crowberto
      (is (not= {:values []}
                (select-keys (params.field-values/get-or-create-field-values!
                              (t2/select-one :model/Field :id (mt/id :people :source)))
                             [:values]))))))

(deftest api-test
  (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                     mcp-sensitive-field-ids           []
                                     mcp-non-sensitive-field-ids       [(mt/id :people :password)]]
    (testing "Admins get the effective list of sensitive fields and the excluded ones"
      (let [{:keys [sensitive excluded]} (mt/user-http-request :crowberto :get 200 "mcp-restrictions/sensitive-fields")]
        (is (=? {:name "PASSWORD" :table_name "USERS" :database_id (mt/id) :source "metadata"}
                (some #(when (= (mt/id :users :password) (:id %)) %) sensitive)))
        (is (not-any? #(= (mt/id :people :password) (:id %)) sensitive))
        (is (=? [{:id (mt/id :people :password) :name "PASSWORD" :table_name "PEOPLE" :database_id (mt/id)}]
                excluded))))
    (testing "Non-admins can't"
      (mt/user-http-request :rasta :get 403 "mcp-restrictions/sensitive-fields"))))

(deftest agent-api-test
  (with-mcp-admin
    (testing "execute_sql on a table with sensitive fields is rejected through the Agent API"
      (let [resp (mt/user-http-request :crowberto :post 403 "agent/v1/execute-sql"
                                       {:database_id (mt/id) :sql "SELECT * FROM PEOPLE"})]
        (is (re-find #"tables with sensitive fields" (pr-str resp)))))))

;;; ------------------------------------------------ Review fixes ------------------------------------------------

(deftest saved-model-selecting-sensitive-field-test
  (testing "Running a saved model that selects a sensitive field masks it instead of rejecting the query"
    (mt/with-temp [:model/Card {card-id :id} {:type          :model
                                              :dataset_query (mt/mbql-query people {:fields   [$id $password]
                                                                                    :order-by [[:asc $id]]
                                                                                    :limit    2})}]
      (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                         mcp-sensitive-field-ids           []
                                         mcp-non-sensitive-field-ids       []]
        ;; The Agent API's execute_question path, which adds the model's saved metadata to the query.
        (let [result (mt/user-http-request :crowberto :post 202 (format "agent/v1/question/%d/query" card-id) {})]
          (is (= "completed" (:status result)))
          (is (= [[1 masked] [2 masked]] (-> result :data :rows))))))))

(deftest masked-values-dont-leak-through-metadata-test
  (testing "Insights and column fingerprints don't reveal sensitive values"
    (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                       mcp-sensitive-field-ids           [(mt/id :orders :total)]
                                       mcp-non-sensitive-field-ids       []]
      (mt/with-test-user :crowberto
        (mcp-restrictions/with-restrictions-enforced
          (let [result (qp/process-query (mt/mbql-query orders {:fields   [$created_at $total]
                                                                :order-by [[:asc $id]]
                                                                :limit    3}))
                total  (some #(when (= "TOTAL" (:name %)) %) (-> result :data :cols))]
            (is (every? nil? (map second (mt/rows result))))
            (is (nil? (:fingerprint total)))
            (is (not-any? #(and (= "TOTAL" (:col %)) (some? (:last-value %)))
                          (-> result :data :insights))))
          (testing "Field fingerprints read from the app DB are dropped too"
            (is (nil? (:fingerprint (t2/select-one :model/Field :id (mt/id :orders :total)))))
            (is (some? (:fingerprint (t2/select-one :model/Field :id (mt/id :orders :subtotal)))))))))))

(deftest exclusions-win-over-same-named-fields-test
  (testing "Excluding a field is honored even when another sensitive field has the same name"
    (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                       mcp-sensitive-field-ids           []
                                       mcp-non-sensitive-field-ids       [(mt/id :people :password)]]
      (mt/with-test-user :crowberto
        (mcp-restrictions/with-restrictions-enforced
          (let [[[_ password]] (run-query (mt/mbql-query people {:fields   [$id $password]
                                                                 :order-by [[:asc $id]]
                                                                 :limit    1}))]
            (is (string? password))
            (is (not= masked password))))))))

(deftest internal-remap-of-sensitive-field-test
  (testing "Display values of a sensitive field are not revealed"
    (mt/with-column-remappings [venues.price {1 "Cheap" 2 "Moderate" 3 "Expensive" 4 "Luxury"}]
      (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                         mcp-sensitive-field-ids           [(mt/id :venues :price)]
                                         mcp-non-sensitive-field-ids       []]
        (mt/with-test-user :crowberto
          (mcp-restrictions/with-restrictions-enforced
            (let [result (qp/process-query (mt/mbql-query venues {:fields   [$id $price]
                                                                  :order-by [[:asc $id]]
                                                                  :limit    2}))
                  rows   (mt/rows result)]
              (is (= [1 2] (map first rows)))
              (is (not-any? #{3 "Expensive" "Moderate" "Cheap" "Luxury"} (mapcat rest rows)))
              (is (not (re-find #"Expensive|Luxury" (pr-str (-> result :data :cols))))))))))))

(deftest field-statistics-test
  (testing "Metabot field statistics are withheld for sensitive fields"
    (mt/with-temporary-setting-values [mcp-sensitive-fields-auto-detect true
                                       mcp-sensitive-field-ids           [(mt/id :orders :total)]
                                       mcp-non-sensitive-field-ids       []]
      (let [{[resource] :resources} (mt/user-http-request
                                     :crowberto :post 200 "agent/v1/read-resource"
                                     {:uris [(format "metabase://table/%d/fields/%d"
                                                     (mt/id :orders) (mt/id :orders :total))]})]
        (is (not (re-find #"159\.3|\"max\"|:max" (pr-str resource))))))))
