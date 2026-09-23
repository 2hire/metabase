(ns metabase.mcp-restrictions.core-test
  (:require
   [clojure.test :refer :all]
   [metabase.lib.core :as lib]
   [metabase.lib.metadata :as lib.metadata]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.mcp.resources :as mcp.resources]
   [metabase.models.interface :as mi]
   [metabase.query-processor.core :as qp]
   [metabase.server.middleware.session :as mw.session]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [metabase.util.json :as json]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :web-server :test-users))

(use-fixtures :each
  (fn [thunk]
    (mcp.resources/with-fallback-template (thunk))))

(def ^:private restricted-message #"not available to MCP clients")

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
        (testing "Native queries naming a restricted table are rejected, whatever the quoting or case"
          (doseq [sql ["SELECT * FROM VENUES"
                       "select name from \"PUBLIC\".\"venues\" limit 1"
                       "SELECT c.* FROM CHECKINS c JOIN venues v ON v.id = c.venue_id"]]
            (is (thrown-with-msg? clojure.lang.ExceptionInfo restricted-message
                                  (run-query (mt/native-query {:query sql})))
                sql)))
        (testing "Native queries that only mention similarly-named identifiers are allowed"
          (is (= [[1000]] (run-query (mt/native-query {:query "SELECT COUNT(VENUE_ID) FROM CHECKINS"})))))))))

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

(deftest session-middleware-test
  (testing "Requests authenticated as an MCP client run with the restrictions enforced"
    (let [handler (mw.session/bind-current-user
                   (fn [_request respond _raise] (respond (mcp-restrictions/enforced?))))
          run     (fn [auth-method]
                    (let [result (promise)]
                      (handler {:embedding/auth-method auth-method} #(deliver result %) identity)
                      @result))]
      (is (true? (run "oauth")))
      (is (true? (run "mcp-ui")))
      (is (false? (run "session")))
      (is (false? (run nil))))))

(deftest agent-api-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (testing "The Agent API rejects native SQL on a restricted table, even for admins"
      (let [resp (mt/user-http-request :crowberto :post 403 "agent/v1/execute-sql"
                                       {:database_id (mt/id)
                                        :sql         "SELECT * FROM VENUES"})]
        (is (re-find restricted-message (pr-str resp)))))
    (testing "Unrestricted tables are still queryable"
      (is (= "completed"
             (:status (mt/user-http-request :crowberto :post 202 "agent/v1/execute-sql"
                                            {:database_id (mt/id)
                                             :sql         "SELECT COUNT(*) FROM CHECKINS"})))))
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

(deftest mcp-tool-call-test
  (mt/with-temporary-setting-values [mcp-restricted-table-ids [(mt/id :venues)]]
    (let [session-id (-> (mcp-request {:jsonrpc "2.0" :method "initialize" :params {} :id 1} {})
                         (get-in [:headers "Mcp-Session-Id"]))
          headers    {"mcp-session-id" session-id}
          call-tool  (fn [tool-name arguments]
                       (get-in (mcp-request {:jsonrpc "2.0"
                                             :method  "tools/call"
                                             :params  {:name tool-name :arguments arguments}
                                             :id      2}
                                            headers)
                               [:body :result]))]
      (mcp-request {:jsonrpc "2.0" :method "notifications/initialized" :params {}} headers)
      (testing "execute_sql over MCP is rejected for a restricted table"
        ;; Query failures come back as the streamed `{:status "failed"}` envelope rather than as an MCP error.
        (let [text (-> (call-tool "execute_sql" {:database_id (mt/id) :sql "SELECT * FROM VENUES"})
                       :content first :text)]
          (is (re-find restricted-message text))
          (is (empty? (-> text json/decode+kw :data :rows)))))
      (testing "execute_sql over MCP works for other tables"
        (let [result (call-tool "execute_sql" {:database_id (mt/id) :sql "SELECT COUNT(*) FROM CHECKINS"})]
          (is (not (:isError result)))
          (is (= [[1000]] (-> result :content first :text json/decode+kw :data :rows))))))))
