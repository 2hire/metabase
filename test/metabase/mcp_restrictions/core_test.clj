(ns metabase.mcp-restrictions.core-test
  (:require
   [clojure.test :refer :all]
   [metabase.lib.core :as lib]
   [metabase.lib.metadata :as lib.metadata]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.mcp.resources :as mcp.resources]
   [metabase.models.interface :as mi]
   [metabase.oauth-server.core :as oauth-server]
   [metabase.parameters.field-values :as params.field-values]
   [metabase.permissions.core :as perms]
   [metabase.query-processor.core :as qp]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [metabase.util.json :as json]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :web-server :test-users))

(use-fixtures :each
  (fn [thunk]
    (mcp.resources/with-fallback-template (thunk))))

(def ^:private restricted-message #"not available to MCP clients")

(def ^:private native-message #"SQL queries are not available to MCP clients")

(defn- run-query [query]
  (mt/rows (qp/process-query query)))

(deftest settings-normalization-test
  (testing "IDs are coerced to a sorted vector of distinct positive integers"
    (mt/with-temporary-setting-values [mcp-restricted-table-ids ["3" 1 1 -2 nil]]
      (is (= [1 3] (mcp-restrictions.settings/mcp-restricted-table-ids)))))
  (testing "Defaults to an empty vector"
    (mt/with-temporary-setting-values [mcp-restricted-database-ids nil]
      (is (= [] (mcp-restrictions.settings/mcp-restricted-database-ids))))))

(deftest restricted-predicates-test
  (mt/with-temporary-setting-values [mcp-restricted-database-ids [(mt/id)]
                                     mcp-restricted-table-ids    [(mt/id :venues)]]
    (testing "Nothing is restricted unless enforced"
      (is (false? (mcp-restrictions/restricted-database? (mt/id))))
      (is (false? (mcp-restrictions/restricted-table? (mt/id) (mt/id :venues)))))
    (mcp-restrictions/with-restrictions-enforced
      (is (true? (mcp-restrictions/restricted-database? (mt/id))))
      (testing "A table in a restricted database is restricted"
        (is (true? (mcp-restrictions/restricted-table? (mt/id) (mt/id :checkins)))))
      (is (false? (mcp-restrictions/restricted-database? Integer/MAX_VALUE))))))

(deftest query-processor-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (mt/with-test-user :crowberto
      (testing "Outside MCP requests nothing changes, even for restricted tables"
        (is (= 100 (count (run-query (mt/mbql-query venues))))))
      (mcp-restrictions/with-restrictions-enforced
        (testing "Admins cannot query a restricted table"
          (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                                (run-query (mt/mbql-query venues)))))
        (testing "Unrestricted tables still work"
          (is (= [[1000]] (run-query (mt/mbql-query checkins {:aggregation [[:count]]})))))
        (testing "An implicit join into a restricted table is rejected"
          (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                                (run-query (mt/mbql-query checkins {:fields [$id $venue_id->venues.name]
                                                                    :limit  1})))))
        (testing "A saved question built on a restricted table cannot be used as a source"
          (mt/with-temp [:model/Card card {:dataset_query (mt/mbql-query venues)}]
            (let [mp (mt/metadata-provider)]
              (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                                    (run-query (lib/query mp (lib.metadata/card mp (:id card)))))))))
        (testing "Native queries are rejected on a database that holds a restricted table, whatever they read"
          ;; Including an identifier escape that names VENUES without spelling it out.
          (doseq [sql ["SELECT * FROM VENUES"
                       "SELECT ID, NAME FROM U&\"VENUE\\0053\""
                       "SELECT COUNT(*) FROM CHECKINS"]]
            (is (thrown-with-msg? clojure.lang.ExceptionInfo native-message
                                  (run-query (mt/native-query {:query sql})))
                sql)))
        (testing "A saved SQL question used as a source is rejected the same way"
          (mt/with-temp [:model/Card card {:dataset_query (mt/native-query {:query "SELECT 1 AS ONE"})}]
            (let [mp (mt/metadata-provider)]
              (is (thrown-with-msg? clojure.lang.ExceptionInfo native-message
                                    (run-query (lib/query mp (lib.metadata/card mp (:id card)))))))))))
    (testing "Native queries still work on databases without restricted tables"
      (mt/with-temp [:model/Database {other-db :id} {:engine :h2}
                     :model/Table    {other-table :id} {:db_id other-db :name "SECRETS"}]
        (mt/with-temporary-setting-values [mcp-restricted-table-ids [other-table]]
          (mt/with-test-user :crowberto
            (mcp-restrictions/with-restrictions-enforced
              (is (= [[1000]] (run-query (mt/native-query {:query "SELECT COUNT(*) FROM CHECKINS"})))))))))))

(deftest restricted-database-query-test
  (mt/with-temporary-setting-values [mcp-restricted-database-ids [(mt/id)]]
    (mt/with-test-user :crowberto
      (mcp-restrictions/with-restrictions-enforced
        (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                              (run-query (mt/mbql-query checkins {:aggregation [[:count]]}))))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                              (run-query (mt/native-query {:query "SELECT 1"}))))))))

(deftest can-read-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (mt/with-test-user :crowberto
      (is (mi/can-read? (t2/select-one :model/Table (mt/id :venues))))
      (mcp-restrictions/with-restrictions-enforced
        (testing "Restricted tables are hidden, their fields too"
          (is (not (mi/can-read? (t2/select-one :model/Table (mt/id :venues)))))
          (is (not (mi/can-query? (t2/select-one :model/Table (mt/id :venues)))))
          (is (not (mi/can-read? (t2/select-one :model/Field (mt/id :venues :name))))))
        (is (mi/can-read? (t2/select-one :model/Table (mt/id :checkins))))
        (is (mi/can-read? :model/Database (mt/id))))))
  (mt/with-temporary-setting-values [mcp-restricted-database-ids [(mt/id)]]
    (mt/with-test-user :crowberto
      (mcp-restrictions/with-restrictions-enforced
        (is (not (mi/can-read? :model/Database (mt/id))))
        (is (not (mi/can-query? :model/Database (mt/id))))
        (is (not (mi/can-read? (t2/select-one :model/Table (mt/id :checkins)))))))))

(deftest remove-restricted-search-results-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (mt/with-temp [:model/Card {venues-card :id}   {:dataset_query (mt/mbql-query venues)}
                   :model/Card {checkins-card :id} {:dataset_query (mt/mbql-query checkins)}]
      (let [results [{:type "table" :id (mt/id :venues) :database_id (mt/id)}
                     {:type "table" :id (mt/id :checkins) :database_id (mt/id)}
                     {:type :question :id venues-card :database_id (mt/id)}
                     {:type "model" :id checkins-card :database_id (mt/id)}
                     {:type "dashboard" :id 1}]]
        (is (= results (mcp-restrictions/remove-restricted-search-results results)))
        (mcp-restrictions/with-restrictions-enforced
          (is (= [{:type "table" :id (mt/id :checkins) :database_id (mt/id)}
                  {:type "model" :id checkins-card :database_id (mt/id)}
                  {:type "dashboard" :id 1}]
                 (mcp-restrictions/remove-restricted-search-results results))))))))

(deftest agent-api-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (testing "The Agent API rejects native SQL on a database that holds a restricted table, even for admins"
      (doseq [sql ["SELECT * FROM VENUES" "SELECT COUNT(*) FROM CHECKINS"]]
        (let [resp (mt/user-http-request :crowberto :post 403 "agent/v1/execute-sql"
                                         {:database_id (mt/id) :sql sql})]
          (is (re-find native-message (pr-str resp)) sql))))
    (testing "Restricted tables cannot be read as resources"
      (let [{[resource] :resources} (mt/user-http-request :crowberto :post 200 "agent/v1/read-resource"
                                                          {:uris [(str "metabase://table/" (mt/id :venues))]})]
        (is (some? (:error resource)))
        (is (nil? (:content resource)))))
    (testing "Restricted tables are left out of the database table listing"
      (let [{[resource] :resources} (mt/user-http-request :crowberto :post 200 "agent/v1/read-resource"
                                                          {:uris [(str "metabase://database/" (mt/id) "/tables")]})
            output                  (pr-str (:content resource))]
        (is (re-find #"CHECKINS" output))
        (is (not (re-find #"VENUES" output)))))
    (testing "The regular API is unaffected"
      (is (= 100 (count (mt/rows (mt/user-http-request :crowberto :post 202 "dataset"
                                                       (mt/mbql-query venues)))))))))

(defn- mcp-request [body extra-headers]
  (client/client-full-response (test.users/username->token :crowberto)
                               :post "metabase-mcp"
                               {:request-options {:headers extra-headers}}
                               body))

(defn- mcp-session-tool-caller
  "Open an MCP session as :crowberto and return a fn that calls a tool in it and returns the MCP result."
  []
  (let [session-id (-> (mcp-request {:jsonrpc "2.0" :method "initialize" :params {} :id 1} {})
                       (get-in [:headers "Mcp-Session-Id"]))
        headers    {"mcp-session-id" session-id}]
    (mcp-request {:jsonrpc "2.0" :method "notifications/initialized" :params {}} headers)
    (fn [tool-name arguments]
      (get-in (mcp-request {:jsonrpc "2.0"
                            :method  "tools/call"
                            :params  {:name tool-name :arguments arguments}
                            :id      2}
                           headers)
              [:body :result]))))

(defn- execute-sql-over-mcp
  "Run `sql` with the `execute_sql` MCP tool and return the decoded result. Query failures come back as the streamed
  `{:status \"failed\"}` envelope rather than as an MCP error."
  [call-tool sql]
  (let [{:keys [isError content]} (call-tool "execute_sql" {:database_id (mt/id) :sql sql})
        text                      (:text (first content))]
    ;; Checks that run before the query come back as a plain-text MCP error instead.
    (if isError
      {:status "failed" :error text}
      (json/decode+kw text))))

(deftest mcp-tool-call-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (let [call-tool (mcp-session-tool-caller)]
      (testing "execute_sql over MCP is rejected on a database that holds a restricted table"
        (let [result (execute-sql-over-mcp call-tool "SELECT * FROM VENUES")]
          (is (= "failed" (:status result)))
          (is (re-find native-message (:error result)))
          (is (empty? (-> result :data :rows)))))))
  (testing "execute_sql over MCP works on databases without restricted tables"
    (mt/with-temp [:model/Database {other-db :id} {:engine :h2}
                   :model/Table    {other-table :id} {:db_id other-db :name "SECRETS"}]
      (mt/with-temporary-setting-values [mcp-restricted-table-ids [other-table]]
        (is (= [[1000]] (-> (execute-sql-over-mcp (mcp-session-tool-caller) "SELECT COUNT(*) FROM CHECKINS")
                            :data :rows)))))))

(defn- admin-setting-value [setting-key]
  (->> (mt/user-http-request :crowberto :get 200 "setting")
       (some #(when (= setting-key (:key %)) (:value %)))))

(deftest admin-settings-round-trip-test
  (testing "The admin settings API drives the restrictions end to end, the way the Admin > AI > MCP page does"
    ;; Restores the original value afterwards.
    (mt/with-temporary-setting-values [mcp-restricted-table-ids []]
      (let [call-tool (mcp-session-tool-caller)]
        (testing "Only admins can change the restrictions"
          (mt/user-http-request :rasta :put 403 "setting/mcp-restricted-table-ids" {:value [(mt/id :venues)]}))
        (is (= "completed" (:status (execute-sql-over-mcp call-tool "SELECT * FROM VENUES"))))
        (testing "Restricting a table from the admin settings API"
          (mt/user-http-request :crowberto :put 204 "setting/mcp-restricted-table-ids" {:value [(mt/id :venues)]})
          (is (= [(mt/id :venues)] (admin-setting-value "mcp-restricted-table-ids")))
          (is (= "failed" (:status (execute-sql-over-mcp call-tool "SELECT * FROM VENUES")))))
        (testing "Clearing the restriction makes the table available again"
          (mt/user-http-request :crowberto :put 204 "setting/mcp-restricted-table-ids" {:value []})
          ;; A value equal to the default is reported as nil; the admin page treats it as no selection.
          (is (empty? (admin-setting-value "mcp-restricted-table-ids")))
          (is (= "completed" (:status (execute-sql-over-mcp call-tool "SELECT * FROM VENUES")))))))
    (mt/with-temporary-setting-values [mcp-restricted-database-ids []]
      (let [call-tool (mcp-session-tool-caller)]
        (testing "Restricting a whole database from the admin settings API"
          (mt/user-http-request :crowberto :put 204 "setting/mcp-restricted-database-ids" {:value [(mt/id)]})
          (is (= [(mt/id)] (admin-setting-value "mcp-restricted-database-ids")))
          (is (= "failed" (:status (execute-sql-over-mcp call-tool "SELECT COUNT(*) FROM CHECKINS")))))))))

;;; ------------------------------------------ Requests with OAuth tokens ------------------------------------------

(defn- save-access-token!
  "Persist an OAuth access token for `username` into the provider backing the embedded authorization server."
  [token username scopes]
  (oidc.store/save-access-token (:token-store (oauth-server/get-provider))
                                token (str (mt/user->id username)) "test-client" (vec scopes)
                                (+ (inst-ms (java.util.Date.)) 3600000) nil))

(defn- bearer-request
  [token method expected-status url & body]
  (:body (apply client/client-full-response method expected-status url
                {:request-options {:headers {"authorization" (str "Bearer " token)}}}
                body)))

(deftest oauth-client-test
  (mt/with-temporary-setting-values [site-url                 "http://localhost:3000"
                                     mcp-restricted-table-ids [(mt/id :venues)]
                                     embedding-secret-key     (apply str (repeat 64 "a"))]
    (oauth-server/reset-provider!)
    ;; `mb:full` is the scope the Metabase CLI asks for: every OAuth token is treated as an AI client.
    (let [token (str "test-token-" (random-uuid))]
      (save-access-token! token :crowberto ["mb:full"])
      (testing "Restricted tables are hidden from the REST API, admins included"
        (let [table-ids (into #{} (map :id) (bearer-request token :get 200 "table"))]
          (is (contains? table-ids (mt/id :checkins)))
          (is (not (contains? table-ids (mt/id :venues)))))
        (bearer-request token :get 403 (str "table/" (mt/id :venues))))
      (testing "Queries through the REST API are restricted"
        (is (re-find restricted-message
                     (str (:error (bearer-request token :post 403 "dataset" (mt/mbql-query venues))))))
        (is (= "completed" (:status (bearer-request token :post 202 "dataset"
                                                    (mt/mbql-query checkins {:aggregation [[:count]]}))))))
      (testing "Writes outside the allowed endpoints are rejected with a JSON 403"
        (doseq [[method url] [[:post "notification"]
                              [:put "setting/mcp-restricted-table-ids"]
                              [:post "api-key"]
                              [:post (str "card/" 1 "/public_link")]]]
          (is (= "mcp_write_denied" (:error (bearer-request token method 403 url {})))
              (str method " " url))))
      (testing "Settings that look like secrets are obfuscated"
        (let [settings (bearer-request token :get 200 "setting")
              value    (some #(when (= "embedding-secret-key" (:key %)) (:value %)) settings)]
          (is (string? value))
          (is (not= (apply str (repeat 64 "a")) value)))))
    (testing "The same user with a session cookie is unaffected"
      (is (= 100 (count (mt/rows (mt/user-http-request :crowberto :post 202 "dataset" (mt/mbql-query venues))))))
      (is (= (apply str (repeat 64 "a"))
             (some #(when (= "embedding-secret-key" (:key %)) (:value %))
                   (mt/user-http-request :crowberto :get 200 "setting")))))))

;;; --------------------------------------------- Other enforcement ----------------------------------------------

(deftest data-permissions-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids    [(mt/id :venues)]
                                     mcp-restricted-database-ids []]
    (mt/with-test-user :crowberto
      (let [admin-id (mt/user->id :crowberto)]
        (is (= :unrestricted (perms/table-permission-for-user admin-id :perms/view-data (mt/id) (mt/id :venues))))
        (mcp-restrictions/with-restrictions-enforced
          (testing "Admins get no data permissions on restricted tables"
            (is (not= :unrestricted
                      (perms/table-permission-for-user admin-id :perms/view-data (mt/id) (mt/id :venues))))
            (is (= :unrestricted
                   (perms/table-permission-for-user admin-id :perms/view-data (mt/id) (mt/id :checkins))))))))))

(deftest field-values-read-only-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (mt/with-test-user :crowberto
      (let [field    (t2/select-one :model/Field :id (mt/id :categories :name))
            existing (params.field-values/get-or-create-field-values! field)]
        (mcp-restrictions/with-restrictions-enforced
          (testing "Restricted tables get no values"
            (is (= [] (:values (params.field-values/get-or-create-field-values!
                                (t2/select-one :model/Field :id (mt/id :venues :name)))))))
          (testing "Cached values are served as they are"
            (is (= (:values existing) (:values (params.field-values/get-or-create-field-values! field)))))
          (testing "Missing values are not computed, so nothing is stored"
            (mt/with-temp [:model/Field {new-field-id :id} {:table_id (mt/id :checkins) :name "NEW_FIELD"
                                                            :base_type :type/Text :has_field_values :list}]
              (is (= [] (:values (params.field-values/get-or-create-field-values!
                                  (t2/select-one :model/Field :id new-field-id)))))
              (is (not (t2/exists? :model/FieldValues :field_id new-field-id))))))))))

(deftest remapping-into-restricted-table-test
  (testing "A display-value remap into a restricted table is skipped rather than failing the query"
    (mt/with-column-remappings [venues.category_id categories.name]
      (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :categories)]]
        (mt/with-test-user :crowberto
          (mcp-restrictions/with-restrictions-enforced
            (let [result (qp/process-query (mt/mbql-query venues {:fields   [$id $category_id]
                                                                  :order-by [[:asc $id]]
                                                                  :limit    2}))]
              (is (= [[1 4] [2 11]] (mt/rows result))))))))))

(deftest card-resource-with-join-test
  (testing "A question that joins a restricted table can't be read as a resource"
    (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
      (mt/with-temp [:model/Card {card-id :id} {:dataset_query (mt/mbql-query checkins
                                                                 {:joins [{:source-table (mt/id :venues)
                                                                           :alias        "v"
                                                                           :condition    [:= $venue_id &v.venues.id]
                                                                           :fields       :all}]})}]
        (let [{[resource] :resources} (mt/user-http-request :crowberto :post 200 "agent/v1/read-resource"
                                                            {:uris [(str "metabase://question/" card-id "/fields")]})]
          (is (some? (:error resource)))
          (is (nil? (:content resource))))))))
