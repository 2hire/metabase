(ns metabase.mcp-restrictions.access-list-test
  (:require
   [clojure.test :refer :all]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.server.middleware.session :as mw.session]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :web-server :test-users))

(deftest settings-test
  (mt/with-temporary-setting-values [mcp-allowed-user-ids  ["2" 1 1]
                                     mcp-allowed-group-ids nil]
    (is (= [1 2] (mcp-restrictions.settings/mcp-allowed-user-ids)))
    (is (= [] (mcp-restrictions.settings/mcp-allowed-group-ids)))))

(deftest user-allowed?-test
  (testing "Everyone is allowed while the access list is empty"
    (mt/with-temporary-setting-values [mcp-allowed-user-ids [] mcp-allowed-group-ids []]
      (is (true? (mcp-restrictions/user-allowed? (mt/user->id :rasta))))))
  (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)] mcp-allowed-group-ids []]
    (testing "Listed users are allowed, others are not"
      (is (true? (mcp-restrictions/user-allowed? (mt/user->id :lucky))))
      (is (false? (mcp-restrictions/user-allowed? (mt/user->id :rasta))))
      (is (false? (mcp-restrictions/user-allowed? nil))))
    (testing "Admins are always allowed"
      (is (true? (mcp-restrictions/user-allowed? (mt/user->id :crowberto))))))
  (testing "Members of a listed group are allowed"
    (mt/with-temp [:model/PermissionsGroup           {group-id :id} {:name "MCP users"}
                   :model/PermissionsGroupMembership _              {:group_id group-id
                                                                     :user_id  (mt/user->id :rasta)}]
      (mt/with-temporary-setting-values [mcp-allowed-user-ids [] mcp-allowed-group-ids [group-id]]
        (is (true? (mcp-restrictions/user-allowed? (mt/user->id :rasta))))
        (is (false? (mcp-restrictions/user-allowed? (mt/user->id :lucky))))))))

(defn- mcp-initialize-status [username]
  (:status (client/client-full-response (test.users/username->token username)
                                        :post "metabase-mcp"
                                        {:request-options {:headers {}}}
                                        {:jsonrpc "2.0" :method "initialize" :params {} :id 1})))

(deftest mcp-endpoint-test
  (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)] mcp-allowed-group-ids []]
    (testing "Users not on the access list are rejected by the MCP server"
      (is (= 403 (mcp-initialize-status :rasta))))
    (testing "Listed users and admins can use it"
      (is (= 200 (mcp-initialize-status :lucky)))
      (is (= 200 (mcp-initialize-status :crowberto)))))
  (testing "With an empty access list everyone can use it"
    (mt/with-temporary-setting-values [mcp-allowed-user-ids [] mcp-allowed-group-ids []]
      (is (= 200 (mcp-initialize-status :rasta))))))

(deftest agent-api-test
  (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)] mcp-allowed-group-ids []]
    (is (= "mcp_access_denied" (:error (mt/user-http-request :rasta :get 403 "agent/v1/ping"))))
    (is (= {:message "pong"} (mt/user-http-request :lucky :get 200 "agent/v1/ping")))))

(deftest oauth-authorize-test
  (testing "Users not on the access list are not issued OAuth authorization codes"
    (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)] mcp-allowed-group-ids []
                                       site-url             "http://localhost:3000"]
      ;; The OAuth routes are served at /oauth, not under /api.
      (binding [client/*url-prefix* ""]
        (is (= "access_denied"
               (:error (mt/user-http-request :rasta :get 403 "oauth/authorize"
                                             :client_id     "some-client"
                                             :redirect_uri  "https://example.com/callback"
                                             :response_type "code"))))
        (is (= "access_denied"
               (:error (mt/user-http-request :rasta :post 403 "oauth/authorize/decision" {}))))))))

(deftest session-middleware-test
  (mt/with-temporary-setting-values [mcp-allowed-user-ids [(mt/user->id :lucky)] mcp-allowed-group-ids []]
    (let [handler (mw.session/bind-current-user
                   (fn [_request respond _raise] (respond {:status 200})))
          status  (fn [auth-method username]
                    (let [result (promise)]
                      (handler {:embedding/auth-method auth-method
                                :metabase-user-id      (mt/user->id username)}
                               #(deliver result %)
                               identity)
                      (:status @result)))]
      (testing "OAuth tokens and MCP UI credentials stop working once the user is off the list"
        (is (= 403 (status "oauth" :rasta)))
        (is (= 403 (status "mcp-ui" :rasta)))
        (is (= 200 (status "oauth" :lucky))))
      (testing "Regular sessions are unaffected"
        (is (= 200 (status "session" :rasta)))))))
