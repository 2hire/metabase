(ns metabase.mcp-restrictions.audit-log-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer :all]
   [java-time.api :as t]
   [metabase.mcp-restrictions.audit-log :as audit-log]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.oauth-server.core :as oauth-server]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [metabase.util.json :as json]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :web-server :test-users))

(defn- mcp-post
  ([username body]
   (mcp-post username body nil))
  ([username body session-id]
   (client/client-full-response (test.users/username->token username)
                                :post "metabase-mcp"
                                {:request-options {:headers (cond-> {"user-agent" "audit-log-test"}
                                                              session-id (assoc "mcp-session-id" session-id))}}
                                body)))

(defn- initialize! [username]
  (let [response (mcp-post username {:jsonrpc "2.0" :method "initialize" :id 1
                                     :params  {:protocolVersion "2025-03-26"
                                               :clientInfo      {:name "Audit Test Client" :version "1.0"}}})]
    (get-in response [:headers "Mcp-Session-Id"])))

(defn- entries-for-session! [session-id]
  (audit-log/flush!)
  (t2/select :model/McpAuditLog :mcp_session_id session-id {:order-by [[:id :asc]]}))

(defn- entries-for-user-agent! [user-agent]
  (audit-log/flush!)
  (t2/select :model/McpAuditLog :user_agent user-agent {:order-by [[:id :asc]]}))

(defn- save-access-token!
  [token user-id scopes]
  (oidc.store/save-access-token (:token-store (oauth-server/get-provider))
                                token (str user-id) "test-client" (vec scopes)
                                (+ (inst-ms (java.util.Date.)) 3600000) nil))

(defn- bearer-request
  "An MCP or REST request authenticated with the OAuth access `token` only, tagged with `user-agent`."
  [token method endpoint expected-status user-agent & [body session-id]]
  (apply client/client-full-response method expected-status endpoint
         {:request-options {:headers (cond-> {"authorization" (str "Bearer " token)
                                              "user-agent"    user-agent}
                                       session-id (assoc "mcp-session-id" session-id))}}
         (when body [body])))

(deftest sanitize-arguments-test
  (testing "Secret-looking keys are masked at any depth"
    (is (= {:query "SELECT 1" :api_key mcp-restrictions/masked-value :nested {:password mcp-restrictions/masked-value
                                                                              :name     "x"}}
           (json/decode+kw (audit-log/sanitize-arguments {:query   "SELECT 1"
                                                          :api_key "sk-123"
                                                          :nested  {:password "hunter2" :name "x"}})))))
  (testing "Secret-looking values are masked wherever they are, and namespaced keys are checked whole"
    (let [secret "sk-live-abcdefghijklmnopqrstuvwx"]
      (is (= {:sql          (str "SELECT * FROM t WHERE api_key = '" mcp-restrictions/masked-value "'")
              :password/new mcp-restrictions/masked-value}
             (json/decode+kw (audit-log/sanitize-arguments {:sql          (str "SELECT * FROM t WHERE api_key = '" secret "'")
                                                            :password/new "hunter2"}))))))
  (testing "Empty arguments are stored as nil"
    (is (nil? (audit-log/sanitize-arguments nil)))
    (is (nil? (audit-log/sanitize-arguments {}))))
  (testing "Long arguments are truncated"
    (is (= 10000 (count (audit-log/sanitize-arguments {:sql (str/join (repeat 20000 "a"))}))))))

(deftest records-mcp-requests-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :rasta)]
        (is (string? session-id))
        (mcp-post :rasta {:jsonrpc "2.0" :method "notifications/initialized"} session-id)
        (mcp-post :rasta {:jsonrpc "2.0" :method "ping" :id 2} session-id)
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 3} session-id)
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/call" :id 4
                          :params  {:name "no_such_tool" :arguments {:query "revenue" :token "abc"}}}
                  session-id)
        (let [entries (entries-for-session! session-id)]
          (testing "Pings and notifications aren't recorded"
            (is (= ["initialize" "tools/list" "tools/call"] (map :method entries))))
          (testing "Every entry has the user, the auth method, the client and the timing"
            (is (every? #(= (mt/user->id :rasta) (:user_id %)) entries))
            (is (every? #(= "session" (:auth_method %)) entries))
            (is (every? #(= "audit-log-test" (:user_agent %)) entries))
            (is (every? #(nat-int? (:duration_ms %)) entries)))
          (let [[init tools-list tool-call] entries]
            (testing "initialize records the client name"
              (is (= "Audit Test Client" (:target init)))
              (is (= "success" (:status init))))
            (testing "tools/list succeeds"
              (is (= "success" (:status tools-list))))
            (testing "a failed tool call is an error, with its masked arguments and the error message"
              (is (= "no_such_tool" (:target tool-call)))
              (is (= "error" (:status tool-call)))
              (is (= {:query "revenue" :token mcp-restrictions/masked-value}
                     (json/decode+kw (:arguments tool-call))))
              (is (str/includes? (:error_message tool-call) "Unknown tool")))))))))

(deftest records-access-list-denials-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   [(mt/user->id :lucky)]
                                       mcp-allowed-group-ids  []]
      (let [session-id (str "denied-test-" (random-uuid))]
        (is (= 403 (:status (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 1} session-id))))
        (is (= 403 (:status (mcp-post :rasta {:jsonrpc "2.0" :method "tools/call" :id 2
                                              :params  {:name      "execute_sql"
                                                        :arguments {:sql "SELECT * FROM salaries"}}}
                                      session-id))))
        (testing "Pings aren't recorded, as when they're allowed"
          (mcp-post :rasta {:jsonrpc "2.0" :method "ping" :id 3} session-id))
        (is (=? [{:user_id       (mt/user->id :rasta)
                  :method        "tools/list"
                  :status        "denied"
                  :error_message (mcp-restrictions/access-denied-message)}
                 {:method    "tools/call"
                  :status    "denied"
                  :target    "execute_sql"
                  :arguments (json/encode {:sql "SELECT * FROM salaries"})}]
                (entries-for-session! session-id)))))))

(deftest disabled-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? false
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :rasta)]
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 2} session-id)
        (is (empty? (entries-for-session! session-id)))))))

(deftest delete-expired-entries-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (let [session-id (str "retention-test-" (random-uuid))
          insert!    (fn [days-ago]
                       (t2/insert-returning-pk! :model/McpAuditLog
                                                {:mcp_session_id session-id
                                                 :auth_method    "session"
                                                 :method         "tools/list"
                                                 :status         "success"
                                                 :created_at     (t/minus (t/offset-date-time) (t/days days-ago))}))
          old-id     (insert! 100)
          recent-id  (insert! 10)]
      (testing "0 keeps everything"
        (mt/with-temporary-setting-values [mcp-audit-log-retention-days 0]
          (audit-log/delete-expired-entries!)
          (is (= #{old-id recent-id} (set (map :id (entries-for-session! session-id)))))))
      (testing "Entries older than the retention are deleted"
        (mt/with-temporary-setting-values [mcp-audit-log-retention-days 90]
          (is (pos? (audit-log/delete-expired-entries!)))
          (is (= #{recent-id} (set (map :id (entries-for-session! session-id))))))))))

(deftest retention-setting-test
  (testing "Anything but a whole number of days, zero or more, is rejected rather than reset to the default"
    (doseq [invalid [-1 "-1" "365.5" "1e3" "" "abc" 1.5 "99999999999999999999"]]
      (testing (pr-str invalid)
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"zero or more"
                              (mt/with-temporary-setting-values [mcp-audit-log-retention-days invalid]))))))
  (testing "Whole numbers are accepted, as numbers or strings"
    (doseq [[value expected] [[0 0] ["30" 30] [" 365 " 365] [7.0 7]]]
      (mt/with-temporary-setting-values [mcp-audit-log-retention-days value]
        (is (= expected (mcp-restrictions.settings/mcp-audit-log-retention-days)))))))

(deftest audit-log-api-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :rasta)]
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 2} session-id)
        (audit-log/flush!)
        (testing "Admins can list the log, filtered and paginated"
          (let [response (mt/user-http-request :crowberto :get 200 "mcp-restrictions/audit-log"
                                               :user-id (mt/user->id :rasta) :method "tools/list" :limit 1)]
            (is (= 1 (:limit response)))
            (is (pos? (:total response)))
            (is (= audit-log/all-methods (:methods response)))
            (is (=? [{:method     "tools/list"
                      :user_id    (mt/user->id :rasta)
                      :user_email "rasta@metabase.com"}]
                    (:data response)))))
        (testing "The page size is capped"
          (is (= 200 (:limit (mt/user-http-request :crowberto :get 200 "mcp-restrictions/audit-log" :limit 100000)))))
        (testing "Invalid status filters are rejected"
          (mt/user-http-request :crowberto :get 400 "mcp-restrictions/audit-log" :status "nope"))
        (testing "Non-admins can't read it"
          (mt/user-http-request :rasta :get 403 "mcp-restrictions/audit-log"))))))

(deftest oauth-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [site-url               "http://localhost:3000"
                                       mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (oauth-server/reset-provider!)
      (let [token      (str "test-token-" (random-uuid))
            user-agent (str "oauth-test-" (random-uuid))]
        (save-access-token! token (mt/user->id :rasta) ["mb:full"])
        (testing "MCP calls made with an OAuth token are recorded as oauth"
          (let [response   (bearer-request token :post "metabase-mcp" 200 user-agent
                                           {:jsonrpc "2.0" :method "initialize" :id 1 :params {}})
                session-id (get-in response [:headers "Mcp-Session-Id"])]
            (bearer-request token :post "metabase-mcp" 200 user-agent
                            {:jsonrpc "2.0" :method "tools/list" :id 2} session-id)
            (is (=? [{:method "initialize" :auth_method "oauth" :status "success"}
                     {:method "tools/list" :auth_method "oauth" :status "success"}]
                    (entries-for-session! session-id)))))
        (testing "REST calls made directly with the token are recorded too, once, and MCP calls aren't recorded twice"
          (bearer-request token :get "user/current" 200 user-agent)
          (is (=? [{:method "initialize"} {:method "tools/list"}
                   {:method "http/get" :target "/api/user/current" :auth_method "oauth" :status "success"}]
                  (entries-for-user-agent! user-agent))))
        (testing "Writes the token may not make are recorded as denied"
          (bearer-request token :put "setting/site-name" 403 user-agent {:value "x"})
          (is (=? {:method "http/put" :target "/api/setting/site-name" :status "denied"}
                  (last (entries-for-user-agent! user-agent)))))
        (testing "When the access list refuses an OAuth client, its MCP calls are recorded as denied"
          (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)]]
            (let [session-id (str "oauth-denied-" (random-uuid))]
              (bearer-request token :post "metabase-mcp" 403 user-agent
                              {:jsonrpc "2.0" :method "tools/call" :id 3 :params {:name "search" :arguments {:q "x"}}}
                              session-id)
              (is (=? [{:method "tools/call" :target "search" :auth_method "oauth" :status "denied"}]
                      (entries-for-session! session-id))))))))))

(deftest deactivated-user-oauth-test
  (mt/with-temporary-setting-values [site-url "http://localhost:3000"]
    (oauth-server/reset-provider!)
    (mt/with-temp [:model/User {user-id :id} {:is_superuser true}]
      (let [token (str "test-token-" (random-uuid))]
        (save-access-token! token user-id ["mb:full"])
        (try
          (is (some? (oauth-server/resolve-access-token token)))
          (t2/update! :model/User user-id {:is_active false})
          (testing "A deactivated user's tokens stop working, on the MCP server and the REST API"
            (is (nil? (oauth-server/resolve-access-token token)))
            (bearer-request token :post "metabase-mcp" 401 "deactivated-test"
                            {:jsonrpc "2.0" :method "initialize" :id 1 :params {}})
            (bearer-request token :get "user/current" 401 "deactivated-test"))
          (finally
            (t2/delete! :model/OAuthAccessToken :user_id user-id)))))))

(deftest refused-before-dispatch-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (testing "Calls with an invalid session are recorded as errors, with the session they sent"
        (let [session-id (str "not-a-session-" (random-uuid))]
          (is (= 404 (:status (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 1} session-id))))
          (is (=? [{:method "tools/list" :user_id (mt/user->id :rasta) :status "error"
                    :error_message "Invalid or expired session"}]
                  (entries-for-session! session-id)))))
      (testing "Batches over the size limit are refused and recorded"
        (let [session-id (initialize! :rasta)]
          (is (= 400 (:status (mcp-post :rasta (vec (for [i (range 101)]
                                                      {:jsonrpc "2.0" :method "tools/list" :id i}))
                                        session-id))))
          (is (= 100 (count (remove #(= "initialize" (:method %)) (entries-for-session! session-id))))))))))

(deftest robustness-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (testing "initialize with params that aren't an object still works"
        (is (= 200 (:status (mcp-post :rasta {:jsonrpc "2.0" :method "initialize" :id 1 :params "x"})))))
      (let [session-id (initialize! :rasta)]
        (testing "Unknown methods are recorded as other, so clients can't grow the method filter"
          (mcp-post :rasta {:jsonrpc "2.0" :method "all" :id 2} session-id)
          (testing "and unknown notifications, which do nothing, aren't recorded"
            (mcp-post :rasta {:jsonrpc "2.0" :method "x1"} session-id)))
        (testing "NUL characters are dropped"
          (mcp-post :rasta {:jsonrpc "2.0" :method "tools/call\u0000" :id 3} session-id))
        (is (=? [{:method "initialize"}
                 {:method "other" :target "all" :status "error"}
                 {:method "other" :target "tools/call" :status "error"}]
                (entries-for-session! session-id)))))))

(deftest failed-query-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :crowberto)
            response   (mcp-post :crowberto {:jsonrpc "2.0" :method "tools/call" :id 2
                                             :params  {:name      "execute_sql"
                                                       :arguments {:database_id (mt/id)
                                                                   :sql         "SELECT * FROM no_such_table"}}}
                                 session-id)]
        (testing "A query that fails while running is a tool error"
          (is (true? (get-in response [:body :result :isError]))))
        (is (=? [{:method "initialize"}
                 {:method "tools/call" :target "execute_sql" :status "error"
                  :error_message #(str/includes? % "NO_SUCH_TABLE")}]
                (entries-for-session! session-id)))))))
