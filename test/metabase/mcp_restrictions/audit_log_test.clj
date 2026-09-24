(ns metabase.mcp-restrictions.audit-log-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer :all]
   [java-time.api :as t]
   [metabase.mcp-restrictions.audit-log :as audit-log]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [metabase.util.json :as json]
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

(defn- entries-for-session [session-id]
  (t2/select :model/McpAuditLog :mcp_session_id session-id {:order-by [[:id :asc]]}))

(deftest sanitize-arguments-test
  (testing "Secret-looking keys are masked at any depth"
    (is (= {:query "SELECT 1" :api_key mcp-restrictions/masked-value :nested {:password mcp-restrictions/masked-value
                                                                              :name     "x"}}
           (json/decode+kw (audit-log/sanitize-arguments {:query   "SELECT 1"
                                                          :api_key "sk-123"
                                                          :nested  {:password "hunter2" :name "x"}})))))
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
        (let [entries (entries-for-session session-id)]
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
        (is (=? [{:user_id       (mt/user->id :rasta)
                  :method        "tools/list"
                  :status        "denied"
                  :error_message (mcp-restrictions/access-denied-message)}]
                (entries-for-session session-id)))))))

(deftest disabled-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? false
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :rasta)]
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 2} session-id)
        (is (empty? (entries-for-session session-id)))))))

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
          (is (= #{old-id recent-id} (set (map :id (entries-for-session session-id)))))))
      (testing "Entries older than the retention are deleted"
        (mt/with-temporary-setting-values [mcp-audit-log-retention-days 90]
          (is (pos? (audit-log/delete-expired-entries!)))
          (is (= #{recent-id} (set (map :id (entries-for-session session-id))))))))))

(deftest retention-setting-test
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"zero or more"
                        (mt/with-temporary-setting-values [mcp-audit-log-retention-days -1]))))

(deftest audit-log-api-test
  (mt/with-model-cleanup [:model/McpAuditLog]
    (mt/with-temporary-setting-values [mcp-audit-log-enabled? true
                                       mcp-allowed-user-ids   []
                                       mcp-allowed-group-ids  []]
      (let [session-id (initialize! :rasta)]
        (mcp-post :rasta {:jsonrpc "2.0" :method "tools/list" :id 2} session-id)
        (testing "Admins can list the log, filtered and paginated"
          (let [response (mt/user-http-request :crowberto :get 200 "mcp-restrictions/audit-log"
                                               :user-id (mt/user->id :rasta) :method "tools/list" :limit 1)]
            (is (= 1 (:limit response)))
            (is (pos? (:total response)))
            (is (contains? (set (:methods response)) "initialize"))
            (is (=? [{:method     "tools/list"
                      :user_id    (mt/user->id :rasta)
                      :user_email "rasta@metabase.com"}]
                    (:data response)))))
        (testing "Invalid status filters are rejected"
          (mt/user-http-request :crowberto :get 400 "mcp-restrictions/audit-log" :status "nope"))
        (testing "Non-admins can't read it"
          (mt/user-http-request :rasta :get 403 "mcp-restrictions/audit-log"))))))
