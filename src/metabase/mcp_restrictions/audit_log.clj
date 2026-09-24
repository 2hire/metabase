(ns metabase.mcp-restrictions.audit-log
  "Audit trail of the requests MCP clients make to the MCP server, stored in `mcp_audit_log`. It has its own table,
  rather than going through `audit_log`, so it works without the audit-app premium feature.

  The MCP transport calls [[record!]] once per JSON-RPC call, including the calls it refuses before dispatching them
  (access list, session, throttling). The session middleware calls it for the REST and Agent API requests AI clients
  make directly, and for the ones it refuses. Recording never fails or delays the request it describes: entries are
  inserted in the background, and errors are logged and swallowed."
  (:require
   [clojure.string :as str]
   [clojure.walk :as walk]
   [java-time.api :as t]
   [metabase.batch-processing.core :as grouper]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.util.json :as json]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def statuses
  "The outcomes a recorded request can have."
  #{"success" "error" "denied"})

(def auth-methods
  "How the client of a recorded request authenticated: a session cookie, an API key, an OAuth access token, the scoped
  credential of the MCP Apps iframe, or an Agent API JWT."
  #{"session" "api-key" "oauth" "mcp-ui" "jwt"})

(def jsonrpc-methods
  "The JSON-RPC methods recorded under their own name. Anything else a client sends is recorded as `other`, with the
  method it sent as the target, so what clients send can't grow the set of methods to filter by."
  ["initialize" "tools/list" "tools/call" "resources/list" "resources/read"])

(def http-methods
  "The methods of the REST and Agent API requests AI clients make directly, rather than through the MCP server. Their
  target is the request URI."
  ["http/get" "http/post" "http/put" "http/patch" "http/delete"])

(def all-methods
  "Every method an entry can have, for filtering."
  (vec (concat jsonrpc-methods ["other"] http-methods)))

(def ^:private method-set (set all-methods))

(def ^:private max-arguments-length 10000)
(def ^:private max-error-length 2000)
(def ^:private max-short-text-length 254)

(defn- truncate [s max-length]
  (when s
    (let [s (str s)]
      (if (> (count s) max-length)
        (str (subs s 0 (dec max-length)) "…")
        s))))

(defn- clean-text
  "`s` as a string that fits in a column of `max-length` characters, without NUL characters (which Postgres can't store
  in text columns) and with anything that looks like a secret masked."
  [s max-length]
  (when (some? s)
    (-> (str s)
        (str/replace "\u0000" "")
        mcp-restrictions/mask-secret-like-value
        (truncate max-length))))

(defn- key-name
  "The full name of map key `k`, namespace included: `json/decode+kw` turns `\"password/new\"` into `:password/new`."
  [k]
  (cond
    (keyword? k) (subs (str k) 1)
    (string? k)  k))

(defn- mask-secrets
  "Replace the value of every map entry whose key looks like it holds a secret (see [[mcp-restrictions/secret-name?]]),
  and anything that looks like a secret inside the other strings (see [[mcp-restrictions/mask-secret-like-value]]), at
  any depth."
  [x]
  (walk/postwalk
   (fn [form]
     (cond
       (map? form)
       (into (empty form)
             (map (fn [[k v]]
                    [k (if (some-> (key-name k) mcp-restrictions/secret-name?)
                         mcp-restrictions/masked-value
                         v)]))
             form)

       (string? form)
       (mcp-restrictions/mask-secret-like-value form)

       :else
       form))
   x))

(defn sanitize-arguments
  "JSON-encode request `arguments` for the audit log, with secrets masked and the result truncated. Returns nil when
  there are no arguments."
  [arguments]
  (when (and (some? arguments)
             (not (and (coll? arguments) (empty? arguments))))
    (truncate (json/encode (mask-secrets arguments)) max-arguments-length)))

(defn- entry->row
  [{:keys [user-id session-id auth-method method target arguments status error-message duration-ms ip-address
           user-agent]}]
  (let [method       (some-> method str)
        known?       (contains? method-set method)
        duration-ms  (some-> duration-ms long)
        auth-method  (some-> auth-method name)]
    {:created_at     (cond-> (t/offset-date-time)
                       ;; when the request was received, not when it was answered
                       duration-ms (t/minus (t/millis duration-ms)))
     :user_id        user-id
     :mcp_session_id (clean-text session-id max-short-text-length)
     :auth_method    (if (contains? auth-methods auth-method) auth-method "session")
     :method         (if known? method "other")
     :target         (clean-text (if known? target (or method target)) max-short-text-length)
     :arguments      (sanitize-arguments arguments)
     :status         (if (contains? statuses status) status "error")
     :error_message  (clean-text error-message max-error-length)
     :duration_ms    (some-> duration-ms (min Integer/MAX_VALUE) int)
     :ip_address     (clean-text ip-address 64)
     :user_agent     (clean-text user-agent max-short-text-length)}))

(defn- insert-rows!
  "Insert a batch of audit log rows. When the batch fails, retry one row at a time so a single bad row doesn't lose
  the others."
  [rows]
  (try
    (t2/insert! :model/McpAuditLog rows)
    (catch Throwable e
      (log/warnf e "Failed to record %d MCP requests in the audit log, retrying them one at a time" (count rows))
      (doseq [row rows]
        (try
          (t2/insert! :model/McpAuditLog row)
          (catch Throwable e
            (log/warnf e "Failed to record MCP request %s in the audit log" (:method row))))))))

(def ^:private queue-capacity 1000)
(def ^:private queue-interval-ms 1000)

(defonce ^:private queue
  (delay (grouper/start! #'insert-rows!
                         :capacity queue-capacity
                         :interval queue-interval-ms)))

(defn record!
  "Record one MCP request in the audit log. `entry` has `:user-id`, `:auth-method` (one of [[auth-methods]]),
  `:method` and `:status` (one of [[statuses]]), and optionally `:session-id`, `:target`, `:arguments` (any
  JSON-encodable value), `:error-message`, `:duration-ms`, `:ip-address` and `:user-agent`. A method not in
  [[all-methods]] is recorded as `other`, with the method as the target.

  Entries are inserted in batches in the background, so they show up in the log up to a second later and are lost on
  a non-graceful shutdown; requests don't wait on the app DB for it. No-op when the audit log is turned off. Never
  throws."
  [entry]
  (try
    (when (mcp-restrictions.settings/mcp-audit-log-enabled?)
      (grouper/submit! @queue (entry->row entry)))
    nil
    (catch Throwable e
      (log/warnf e "Failed to record MCP request %s in the audit log" (:method entry))
      nil)))

(defn flush!
  "Block until every entry recorded so far is in the app DB."
  []
  (grouper/flush! @queue))

;;; ------------------------------------------------------ Reading -------------------------------------------------

(defn- where-clause
  [{:keys [user-id method status]}]
  (let [clauses (cond-> []
                  user-id (conj [:= :a.user_id user-id])
                  method  (conj [:= :a.method method])
                  status  (conj [:= :a.status status]))]
    (when (seq clauses)
      (into [:and] clauses))))

(defn list-entries
  "A page of audit log entries, newest first, with the user's name and email. `filters` may have `:user-id`,
  `:method` and `:status`. Returns `{:total :data}`."
  [filters limit offset]
  (let [where (where-clause filters)
        total (:count (t2/query-one (cond-> {:select [[[:count :*] :count]]
                                             :from   [[:mcp_audit_log :a]]}
                                      where (assoc :where where))))
        rows  (t2/query (cond-> {:select    [:a.id :a.created_at :a.user_id :a.mcp_session_id :a.auth_method
                                             :a.method :a.target :a.arguments :a.status :a.error_message
                                             :a.duration_ms :a.ip_address :a.user_agent
                                             [:u.email :user_email]
                                             [:u.first_name :user_first_name]
                                             [:u.last_name :user_last_name]]
                                 :from      [[:mcp_audit_log :a]]
                                 :left-join [[:core_user :u] [:= :a.user_id :u.id]]
                                 :order-by  [[:a.created_at :desc] [:a.id :desc]]
                                 :limit     limit
                                 :offset    offset}
                          where (assoc :where where)))]
    {:total (or total 0)
     :data  (mapv #(into {} %) rows)}))

;;; ----------------------------------------------------- Retention ------------------------------------------------

(def ^:private delete-batch-size 10000)

(defn delete-expired-entries!
  "Delete the entries older than [[mcp-restrictions.settings/mcp-audit-log-retention-days]], in batches. No-op when
  the retention is 0 (keep forever). Returns the number of rows deleted."
  []
  (let [days (mcp-restrictions.settings/mcp-audit-log-retention-days)]
    (if-not (pos? (or days 0))
      0
      (let [cutoff (t/minus (t/offset-date-time) (t/days days))]
        (loop [total 0]
          (let [ids     (t2/select-pks-vec :model/McpAuditLog {:where    [:< :created_at cutoff]
                                                               :order-by [[:id :asc]]
                                                               :limit    delete-batch-size})
                deleted (if (seq ids)
                          (t2/delete! :model/McpAuditLog :id [:in ids])
                          0)
                total   (+ total (long deleted))]
            (if (= (count ids) delete-batch-size)
              (recur total)
              total)))))))
