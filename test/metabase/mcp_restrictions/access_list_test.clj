(ns metabase.mcp-restrictions.access-list-test
  (:require
   [clojure.string :as str]
   [clojure.test :refer :all]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.oauth-server.core :as oauth-server]
   [metabase.test :as mt]
   [metabase.test.data.users :as test.users]
   [metabase.test.fixtures :as fixtures]
   [metabase.test.http-client :as client]
   [oidc-provider.store :as oidc.store]
   [toucan2.core :as t2]))

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

(defn- save-access-token!
  [token username scopes]
  (oidc.store/save-access-token (:token-store (oauth-server/get-provider))
                                token (str (mt/user->id username)) "test-client" (vec scopes)
                                (+ (inst-ms (java.util.Date.)) 3600000) nil))

;; The example S256 challenge from RFC 7636 §4.6; public clients must use PKCE.
(def ^:private pkce-challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

(deftest oauth-test
  (mt/with-temporary-setting-values [site-url              "http://localhost:3000"
                                     mcp-allowed-user-ids  [(mt/user->id :lucky)]
                                     mcp-allowed-group-ids []]
    (oauth-server/reset-provider!)
    (testing "Users not on the access list get access_denied sent back to the client, not a consent page"
      (let [[{client-id :client_id}] (t2/insert-returning-instances!
                                      :model/OAuthClient
                                      {:client_id         (str (random-uuid))
                                       :client_type       "public"
                                       :redirect_uris     ["https://example.com/callback"]
                                       :client_name       "Test MCP client"
                                       :grant_types       ["authorization_code"]
                                       :response_types    ["code"]
                                       :scopes            ["profile"]
                                       :application_type  "native"
                                       :registration_type "static"})]
        (try
          ;; The OAuth routes are served at /oauth, not under /api.
          (binding [client/*url-prefix* ""]
            (let [location (get-in (mt/user-http-request-full-response
                                    :rasta :get 302 "oauth/authorize"
                                    :client_id     client-id
                                    :redirect_uri  "https://example.com/callback"
                                    :response_type "code"
                                    :scope         "profile"
                                    :state         "s1"
                                    :code_challenge        pkce-challenge
                                    :code_challenge_method "S256")
                                   [:headers "Location"])]
              (is (str/starts-with? location "https://example.com/callback?"))
              (is (str/includes? location "error=access_denied"))
              (is (str/includes? location "state=s1")))
            (testing "Listed users get the consent page"
              (is (str/includes? (:body (mt/user-http-request-full-response
                                         :lucky :get 200 "oauth/authorize"
                                         :client_id     client-id
                                         :redirect_uri  "https://example.com/callback"
                                         :response_type "code"
                                         :scope         "profile"
                                         :code_challenge        pkce-challenge
                                         :code_challenge_method "S256"))
                                 "/oauth/authorize/decision"))))
          (finally
            (t2/delete! :model/OAuthClient :client_id client-id)))))
    (testing "OAuth tokens stop working on the whole API once the user is off the list, with a JSON 403"
      (let [rasta-token (str "test-token-" (random-uuid))
            lucky-token (str "test-token-" (random-uuid))
            request     (fn [token expected-status]
                          (:body (client/client-full-response
                                  :get expected-status "user/current"
                                  {:request-options {:headers {"authorization" (str "Bearer " token)}}})))]
        (save-access-token! rasta-token :rasta ["mb:full"])
        (save-access-token! lucky-token :lucky ["mb:full"])
        (is (= "mcp_access_denied" (:error (request rasta-token 403))))
        (is (= (mt/user->id :lucky) (:id (request lucky-token 200))))))))
