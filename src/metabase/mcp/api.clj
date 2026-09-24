(ns metabase.mcp.api
  "MCP (Model Context Protocol) Streamable HTTP transport handler.
   Exposes Metabase's agent tools via JSON-RPC 2.0 over each of the MCP endpoints."
  (:require
   [clojure.core.async :as a]
   [clojure.string :as str]
   [clojure.walk :as walk]
   [compojure.response :as compojure.response]
   [metabase.api.common :as api]
   [metabase.api.macros.scope :as scope]
   [metabase.api.open-api :as open-api]
   [metabase.mcp-restrictions.audit-log :as mcp.audit-log]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp.core :as mcp]
   [metabase.mcp.resources :as mcp.resources]
   [metabase.mcp.session :as mcp.session]
   [metabase.mcp.tools :as mcp.tools]
   [metabase.mcp.validation :as mcp.validation]
   [metabase.oauth-server.core :as oauth-server]
   [metabase.request.core :as request]
   [metabase.server.middleware.security :as mw.security]
   [metabase.server.streaming-response :as streaming-response]
   [metabase.system.core :as system]
   [metabase.util :as u]
   [metabase.util.json :as json]
   [metabase.util.log :as log]
   [throttle.core :as throttle])
  (:import
   (java.io BufferedWriter OutputStreamWriter)
   (java.nio.charset StandardCharsets)))

(set! *warn-on-reflection* true)

;;; -------------------------------------------------- Auth --------------------------------------------------------

(defn- validate-bearer-token
  "Look up and validate an OAuth bearer token. Returns `{:user-id <int> :scopes <set>}` on success, nil on failure.
   Delegates to the shared resolver so MCP and the core session middleware agree on token validity and scopes."
  [token-string]
  (oauth-server/resolve-access-token token-string))

;;; ------------------------------------------------- JSON-RPC 2.0 --------------------------------------------------

(def ^:private server-info
  {:name    "metabase"
   :version "0.1.0"})

(def ^:private protocol-version "2025-03-26")

(defn- jsonrpc-response [id result]
  {:jsonrpc "2.0" :id id :result result})

(defn- jsonrpc-error [id code message]
  {:jsonrpc "2.0" :id id :error {:code code :message message}})

(defn- handle-initialize [id params]
  (when-let [client-info (:clientInfo params)]
    (log/infof "MCP client connected: %s %s" (:name client-info) (:version client-info)))
  (jsonrpc-response
   id
   {:protocolVersion protocol-version
    :capabilities    {:tools {:listChanged true} :resources {}}
    :serverInfo      server-info}))

(defn- mcp-app-ui-capability?
  "Return true if initialize params advertise support for MCP Apps HTML resources."
  [params]
  ;; `json/decode+kw` preserves the slash in the JSON extension key `"io.modelcontextprotocol/ui"` as the
  ;; namespaced keyword `:io.modelcontextprotocol/ui`.
  (contains?
   (set (get-in params [:capabilities :extensions :io.modelcontextprotocol/ui :mimeTypes]))
   "text/html;profile=mcp-app"))

(defn- handle-tools-list [id _params session-id token-scopes]
  (let [supports-mcp-ui? (mcp.session/supports-mcp-ui? session-id)]
    (jsonrpc-response id {:tools (mcp.tools/list-tools token-scopes {:supports-mcp-ui?
                                                                     supports-mcp-ui?})})))

(defn- handle-tools-call [id params session-id token-scopes]
  (let [tool-name (:name params)
        arguments (or (:arguments params) {})
        supports-mcp-ui? (mcp.session/supports-mcp-ui? session-id)]
    (jsonrpc-response id (mcp.tools/call-tool token-scopes
                                              session-id
                                              tool-name
                                              arguments
                                              {:supports-mcp-ui?
                                               supports-mcp-ui?}))))

(defn- handle-resources-list [id _params token-scopes]
  (jsonrpc-response id (mcp.resources/list-resources token-scopes)))

(defn- handle-resources-read [id params token-scopes]
  (let [uri (:uri params)]
    (if (or (not (string? uri)) (str/blank? uri))
      (jsonrpc-error id -32602 "Missing required parameter: uri")
      (let [result (mcp.resources/read-resource uri token-scopes {})]
        (case (:status result)
          (:not-found :scope-denied) (jsonrpc-error id -32602 "Resource not found")
          :ok                        (jsonrpc-response id {:contents (:contents result)}))))))

(defn- handle-ping [id _params]
  (jsonrpc-response id {}))

(defn- dispatch-request*
  "Dispatch a single JSON-RPC request. Returns a response map or nil for notifications."
  [{:keys [id method params] :as _msg} session-id token-scopes]
  (try
    (case method
      "notifications/initialized" nil
      "tools/list"                (handle-tools-list id params session-id token-scopes)
      "tools/call"                (handle-tools-call id params session-id token-scopes)
      "resources/list"            (handle-resources-list id params token-scopes)
      "resources/read"            (handle-resources-read id params token-scopes)
      "ping"                      (handle-ping id params)
      (if id
        (jsonrpc-error id -32601 (str "Method not found: " method))
        nil))
    (catch Throwable e
      (log/error "Error dispatching JSON-RPC method" method (ex-message e))
      (jsonrpc-error id -32603 (or (ex-message e) "Internal error")))))

;;; ------------------------------------------------- Audit log ----------------------------------------------------

(def ^:private known-methods
  "The JSON-RPC methods [[dispatch-request*]] runs whether or not the message has an id."
  #{"initialize" "tools/list" "tools/call" "resources/list" "resources/read"})

(defn- audited-message?
  "Whether a JSON-RPC message goes in the MCP audit log. Keepalive pings and client notifications don't, and neither do
  messages without an id for a method the server doesn't know, which it ignores."
  [{:keys [id method] :as msg}]
  (and (map? msg)
       (not= method "ping")
       (not (and (string? method) (str/starts-with? method "notifications/")))
       (or (some? id) (contains? known-methods method))))

(defn- audit-auth-method
  "How a `request` the session middleware authenticated did it, as recorded in the MCP audit log: session cookie, API
  key or OAuth access token."
  [request]
  (or (:metabase-credential request) :session))

(defn- audit-context
  "The parts of an MCP HTTP request every audit log entry for it shares."
  [user-id request]
  {:user-id     user-id
   :auth-method (:mcp-auth-method request)
   :session-id  (get-in request [:headers "mcp-session-id"])
   :ip-address  (request/ip-address request)
   :user-agent  (get-in request [:headers "user-agent"])})

(defn- audit-target [method params]
  (when (map? params)
    (case method
      "tools/call"     (:name params)
      "resources/read" (:uri params)
      "initialize"     (get-in params [:clientInfo :name])
      nil)))

(defn- audit-arguments [method params]
  (when (map? params)
    (case method
      "tools/call" (:arguments params)
      "initialize" (select-keys params [:protocolVersion :clientInfo])
      nil)))

(defn- response-error
  "The error message a JSON-RPC `response` carries, or nil when it succeeded. Tool failures come back as a result with
  `isError`, not as a JSON-RPC error; failed queries carry their error in the structured content."
  [response]
  (or (get-in response [:error :message])
      (when (get-in response [:result :isError])
        (let [structured-error (get-in response [:result :structuredContent :error])]
          (or (when (string? structured-error) (not-empty structured-error))
              (not-empty (str/join "\n" (keep :text (get-in response [:result :content]))))
              "Tool call failed")))))

(defn- record-message!
  "Record a JSON-RPC message in the MCP audit log with the outcome in `entry` (`:status`, and optionally
  `:error-message` and `:duration-ms`). Never throws."
  [audit-ctx {:keys [method params] :as msg} entry]
  (try
    (mcp.audit-log/record! (merge audit-ctx
                                  {:method    (when (map? msg) method)
                                   :target    (audit-target method params)
                                   :arguments (audit-arguments method params)}
                                  entry))
    (catch Throwable e
      (log/warn e "Failed to record an MCP request in the audit log"))))

(defn- record-call!
  "Record a JSON-RPC call and the response it got in the MCP audit log."
  [audit-ctx msg response started-at]
  (let [error-message (response-error response)]
    (record-message! audit-ctx msg {:status        (if error-message "error" "success")
                                    :error-message error-message
                                    :duration-ms   (u/since-ms started-at)})))

(defn- record-refused!
  "Record the JSON-RPC calls in a POST `body` that were refused before being dispatched, each with `status` and
  `message`. A body that is neither an object nor an array is recorded once, as an `other` call."
  [audit-ctx body status message]
  (let [body     (walk/keywordize-keys body)
        messages (cond
                   (sequential? body) body
                   (map? body)        [body]
                   :else              [nil])]
    (doseq [msg messages
            :when (or (nil? msg) (audited-message? msg))]
      (record-message! audit-ctx msg {:status status :error-message message}))))

(defn- dispatch-request
  "Dispatch a single JSON-RPC request and record it in the MCP audit log. Returns a response map or nil for
  notifications. Nothing is recorded without an `audit-ctx`."
  ([msg session-id token-scopes]
   (dispatch-request msg session-id token-scopes nil))
  ([msg session-id token-scopes audit-ctx]
   (let [started-at (u/start-timer)
         response   (dispatch-request* msg session-id token-scopes)]
     (when (and audit-ctx (audited-message? msg))
       (record-call! (assoc audit-ctx :session-id session-id) msg response started-at))
     response)))

;;; ----------------------------------------------------- SSE ------------------------------------------------------

(defn- accepts-sse?
  "Return true if the request's Accept header includes text/event-stream."
  [request]
  (some-> (get-in request [:headers "accept"])
          (str/includes? "text/event-stream")))

(defn- sse-body
  "Format a sequence of JSON-RPC messages as SSE event text."
  [messages]
  (str/join (for [message messages]
              (str "event: message\ndata: " (json/encode message) "\n\n"))))

;;; -------------------------------------------------- Responses ---------------------------------------------------

(defn- json-response
  ([status body]
   (json-response status body nil))
  ([status body extra-headers]
   {:status  status
    :headers (merge {"Content-Type" "application/json"} extra-headers)
    :body    (json/encode body)}))

(defn- sse-response
  "Return a plain Ring response with SSE-formatted body for POST requests."
  ([messages]
   (sse-response messages nil))
  ([messages extra-headers]
   {:status  200
    :headers (merge {"Content-Type"  "text/event-stream"
                     "Cache-Control" "no-cache"}
                    extra-headers)
    :body    (sse-body messages)}))

;;; ------------------------------------------------- Validation --------------------------------------------------

(defn- normalize-domain
  "Extract and lowercase the domain from a URL or Host-style header value.
   Bracketed IPv6 forms (`[::1]:3000`) and ports are handled correctly. Returns nil for unparsable input.
   Uses `try-parse-url` (the silent variant) — `Origin`/`Host` are client-controlled, so malformed inputs
   are expected and shouldn't spam the error logs."
  [url]
  (some-> url str mw.security/try-parse-url :domain u/lower-case-en))

(defn- same-origin-host? [origin host]
  (let [origin-domain (normalize-domain origin)]
    (and (some? origin-domain) (= origin-domain (normalize-domain host)))))

(defn- approved-mcp-origin? [origin]
  ;; Pre-lowercase both inputs so DNS hostname matching is case-insensitive (per RFC) and so mixed-case
  ;; schemes still match `try-parse-url`'s lowercase-only `https?|app|capacitor` regex.
  (boolean
   (or (mcp/sandbox-origin? origin)
       (when-let [approved-origins (not-empty (mcp/cors-origins))]
         (when-let [origin-url (mw.security/try-parse-url (u/lower-case-en origin))]
           (some (fn [approved-origin]
                   (and (mw.security/approved-domain? (:domain origin-url) (:domain approved-origin))
                        (mw.security/approved-protocol? (:protocol origin-url) (:protocol approved-origin))
                        (mw.security/approved-port? (:port origin-url) (:port approved-origin))))
                 (mw.security/parse-approved-origins (u/lower-case-en approved-origins))))))))

(defn- validate-origin
  "Validate the Origin header to prevent DNS rebinding attacks (MCP spec requirement).
   Returns a 403 response if Origin is present and is neither same-host nor an explicitly configured
   MCP app origin. Non-browser clients that omit the Origin header are allowed through."
  [request]
  (when-let [origin (get-in request [:headers "origin"])]
    (let [host (get-in request [:headers "host"])]
      (when-not (or (same-origin-host? origin host)
                    (approved-mcp-origin? origin))
        (json-response 403 (jsonrpc-error nil -32600 "Origin not allowed"))))))

(defn- require-valid-session
  "Validate the Mcp-Session-Id header value. Checks UUID format and, when a
   `core_session` has been materialized, verifies it belongs to `user-id`."
  [user-id session-id]
  (cond
    (str/blank? session-id)
    {:error (json-response 400 (jsonrpc-error nil -32600 "Missing Mcp-Session-Id header"))}

    (not (mcp.session/valid-id? session-id))
    {:error (json-response 404 (jsonrpc-error nil -32600 "Invalid or expired session"))}

    (not (mcp.session/owned-by-user? session-id user-id))
    {:error (json-response 404 (jsonrpc-error nil -32600 "Invalid or expired session"))}

    :else
    {:session-id session-id}))

;;; -------------------------------------------------- Handlers ---------------------------------------------------

(def ^:private max-batch-size
  "The most JSON-RPC messages one POST may carry. The throttle counts HTTP requests, so without a cap one request could
  run and record any number of calls."
  100)

(defn- refuse-post
  "Record the calls in a POST that is refused before dispatch, and return the `error` response."
  [audit-ctx body error]
  (record-refused! audit-ctx body "error" (some-> (:body error) json/decode+kw :error :message))
  error)

(defn- handle-post
  "Handle a POST request containing one or more JSON-RPC messages."
  [user-id request]
  (let [body       (walk/keywordize-keys (:body request))
        session-id (get-in request [:headers "mcp-session-id"])
        batch?     (sequential? body)
        audit-ctx  (audit-context user-id request)]
    (cond
      (nil? body)
      (refuse-post audit-ctx body (json-response 400 (jsonrpc-error nil -32700 "Parse error: empty body")))

      (and (not (map? body)) (not batch?))
      (refuse-post audit-ctx body (json-response 400 (jsonrpc-error nil -32600 "Invalid request: expected object or array")))

      ;; JSON-RPC 2.0: empty batch is invalid
      (and batch? (empty? body))
      (json-response 400 (jsonrpc-error nil -32600 "Invalid request: empty batch"))

      (and batch? (> (count body) max-batch-size))
      (refuse-post audit-ctx (take max-batch-size body)
                   (json-response 400 (jsonrpc-error nil -32600 (str "Invalid request: a batch can hold at most "
                                                                     max-batch-size " messages"))))

      ;; MCP spec: "The initialize request MUST NOT be part of a JSON-RPC batch"
      (and batch? (some #(= "initialize" (:method %)) body))
      (refuse-post audit-ctx body (json-response 400 (jsonrpc-error nil -32600 "initialize must not be batched")))

      ;; Initialize: create session and return response with session header
      (and (not batch?) (= "initialize" (:method body)))
      (let [started-at       (u/start-timer)
            params           (:params body)
            supports-mcp-ui? (mcp-app-ui-capability? params)
            session-id       (mcp.session/create! user-id {:supports-mcp-ui?
                                                           supports-mcp-ui?})
            init-response (handle-initialize (:id body) (:params body))]
        (record-call! (assoc audit-ctx :session-id session-id) body init-response started-at)
        (if (accepts-sse? request)
          (sse-response [init-response] {"Mcp-Session-Id" session-id})
          (json-response 200 init-response {"Mcp-Session-Id" session-id})))

      ;; All other requests require a valid session
      :else
      (let [{:keys [error]} (require-valid-session user-id session-id)]
        (if error
          (refuse-post audit-ctx body error)
          (let [messages  (if batch? body [body])
                responses (into [] (keep #(dispatch-request % session-id (:token-scopes request) audit-ctx)) messages)]
            (cond
              (empty? responses)
              {:status 202 :headers {} :body ""}

              (accepts-sse? request)
              (sse-response responses)

              (and (not batch?) (= 1 (count responses)))
              (json-response 200 (first responses))

              :else
              (json-response 200 responses))))))))

(def ^:private tools-list-changed-notification
  {:jsonrpc "2.0" :method "notifications/tools/list_changed"})

(defn- handle-get
  "Handle a GET request for SSE stream (keepalive for server-initiated notifications).
   Polls the tool manifest hash on each keepalive tick — if the visible tool set has
   changed since the previous tick, emits an MCP `notifications/tools/list_changed`
   message so the client knows to refetch `tools/list`. Stateless: each connection
   tracks its own last-seen hash; no shared registry."
  [user-id request respond raise]
  (let [session-id (get-in request [:headers "mcp-session-id"])
        token-scopes (:token-scopes request)
        {:keys [error]} (require-valid-session user-id session-id)]
    (cond
      (some? error)
      (respond error)

      :else
      (let [resp (streaming-response/streaming-response
                  {:content-type "text/event-stream"
                   :headers      {"Cache-Control" "no-cache"}
                   :status       200}
                  [os canceled-chan]
                   (let [writer (BufferedWriter. (OutputStreamWriter. os StandardCharsets/UTF_8))]
                     (loop [last-hash (mcp.tools/tools-hash token-scopes)]
                       (when-not (a/poll! canceled-chan)
                         (.write writer ": keepalive\n\n")
                         (.flush writer)
                         (Thread/sleep 30000)
                         (let [current-hash (mcp.tools/tools-hash token-scopes)]
                           (when (not= current-hash last-hash)
                             (.write writer ^String (sse-body [tools-list-changed-notification]))
                             (.flush writer))
                           (recur current-hash))))))]
        (compojure.response/send* resp request respond raise)))))

(defn- handle-delete
  "Handle a DELETE request to tear down a session."
  [user-id request]
  (let [session-id-header (get-in request [:headers "mcp-session-id"])
        {:keys [session-id error]} (require-valid-session user-id session-id-header)]
    (or error
        (do (mcp.session/delete! session-id user-id)
            {:status 200 :headers {"Content-Type" "application/json"} :body ""}))))

;;; -------------------------------------------------- Throttling --------------------------------------------------

;; MCP is auth-gated (session cookie or bearer token), so the risk is lower than the
;; unauthenticated OAuth endpoints. The threshold is generous to accommodate users running
;; multiple concurrent agents (e.g. 5 agents × 200 req/min). throttle/check counts every
;; request (not just failures) which is correct here — we want to cap total throughput
;; regardless of success to prevent resource exhaustion from a compromised token.
(def ^:private one-minute-ms (* 60 1000))

(def ^:private mcp-throttler
  (throttle/make-throttler :user-id :attempts-threshold 1000 :attempt-ttl-ms one-minute-ms))

(defn- check-throttle
  "Returns a 429 JSON-RPC response if rate-limited, nil otherwise."
  [user-id]
  (try
    (throttle/check mcp-throttler user-id)
    nil
    (catch clojure.lang.ExceptionInfo e
      (let [message       (ex-message e)
            retry-seconds (some->> message (re-find #"(\d+) seconds") second)]
        (cond-> (json-response 429 (jsonrpc-error nil -32000 message))
          retry-seconds (assoc-in [:headers "Retry-After"] retry-seconds))))))

;;; ---------------------------------------------------- Handler ---------------------------------------------------

(def ^:private throttle-recorded-at
  "When a throttled request was last recorded in the MCP audit log, by user ID. A throttled client keeps retrying, so
  only the first refusal per throttle window is recorded."
  (atom {}))

(defn- record-throttled!
  "Record a request refused by the throttle in the MCP audit log, at most once per user per throttle window."
  [user-id request throttle-err]
  (let [now      (System/currentTimeMillis)
        [old _]  (swap-vals! throttle-recorded-at
                             (fn [recorded]
                               (if (< (- now (get recorded user-id 0)) one-minute-ms)
                                 recorded
                                 (assoc recorded user-id now))))]
    (when (>= (- now (get old user-id 0)) one-minute-ms)
      (record-refused! (audit-context user-id request)
                       (when (= :post (:request-method request)) (:body request))
                       "error"
                       (some-> (:body throttle-err) json/decode+kw :error :message)))))

(defn- record-access-denied!
  "Record the JSON-RPC calls of a POST the MCP access list refused in the MCP audit log. The SSE stream (GET) and
  session teardown (DELETE) aren't calls and are left out, as when they're allowed."
  [user-id request message]
  (when (= :post (:request-method request))
    (record-refused! (audit-context user-id request) (:body request) "denied" message)))

;; Source of truth for the route aliases — keep in sync with the route-map in
;; [[metabase.api-routes.routes]] and resource-metadata endpoints in [[metabase.oauth-server.api.metadata]].
(def ^:private endpoint-paths
  "URL paths that serve the MCP endpoint, relative to site-url.
   `/api/metabase-mcp` is canonical (the advertised URL); `/api/mcp` is a legacy alias kept for
   back-compat with existing clients."
  #{"/api/metabase-mcp" "/api/mcp"})

(defn- www-authenticate-discovery
  "Build the `WWW-Authenticate` header advertising OAuth discovery for the path the client hit.
   A client connecting via an alias is pointed at that same alias as the protected resource."
  [request]
  ;; Routing matches on the first path segment, so a trailing slash (e.g. `/api/metabase-mcp/`) still
  ;; reaches the handler — strip it so the alias is recognized rather than falling back to canonical.
  (let [uri  (str/replace (:uri request) #"/+$" "")
        path (if (contains? endpoint-paths uri) uri "/api/metabase-mcp")]
    (str "Bearer realm=\"mcp\" resource_metadata=\"" (system/site-url) "/.well-known/oauth-protected-resource" path "\"")))

(def +mcp-enabled
  "Wrap routes so they may only be accessed when the MCP server is enabled."
  mcp.validation/+mcp-enabled)

(def ^{:arglists '([request respond raise])} handler
  "Ring async handler for the MCP endpoint.
   Uses JSON-RPC 2.0 over HTTP rather than REST, so the OpenAPI spec is empty."
  (open-api/handler-with-open-api-spec
   (fn [request respond raise]
     (let [origin-error (validate-origin request)
           bearer-token (oauth-server/extract-bearer-token request)
           session-auth api/*current-user-id*
           token-scopes (:token-scopes request)]
       (letfn [(dispatch [user-id token-scopes auth-method]
                 (request/with-current-user user-id
                   (let [request (assoc request :token-scopes token-scopes :mcp-auth-method auth-method)]
                     (if-let [throttle-err (check-throttle user-id)]
                       (do (record-throttled! user-id request throttle-err)
                           (respond throttle-err))
                       (try
                         (cond
                           (not (mcp-restrictions/user-allowed? user-id))
                           (let [message (mcp-restrictions/access-denied-message)]
                             (record-access-denied! user-id request message)
                             (respond (json-response 403 (jsonrpc-error nil -32603 message))))

                           (= :post (:request-method request))
                           (respond (handle-post user-id request))

                           (= :get (:request-method request))
                           (handle-get user-id request respond raise)

                           (= :delete (:request-method request))
                           (respond (handle-delete user-id request))

                           :else
                           (respond (json-response 405 (jsonrpc-error nil -32600 "Method not allowed"))))
                         (catch Throwable e
                           (raise e)))))))]
         (cond
           (some? origin-error)
           (respond origin-error)

           ;; Respect the scope set attached to an authenticated request. Sessions without one
           ;; retain unrestricted access.
           session-auth
           (dispatch session-auth (or token-scopes #{::scope/unrestricted}) (audit-auth-method request))

           ;; Bearer token auth — validate and extract scopes
           bearer-token
           (if-let [{:keys [user-id scopes]} (validate-bearer-token bearer-token)]
             (dispatch user-id scopes :oauth)
             (respond (json-response 401 (jsonrpc-error nil -32603 "Invalid bearer token")
                                     {"WWW-Authenticate" "Bearer error=\"invalid_token\""})))

           ;; No auth at all — return 401 with discovery
           :else
           (respond (json-response 401 (jsonrpc-error nil -32603 "Authentication required")
                                   {"WWW-Authenticate" (www-authenticate-discovery request)}))))))
   (constantly nil)))
