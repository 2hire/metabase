(ns metabase.mcp-restrictions.audit-log
  "Audit trail of the requests MCP clients make to the MCP server, stored in `mcp_audit_log`. It has its own table,
  rather than going through `audit_log`, so it works without the audit-app premium feature.

  The MCP transport calls [[record!]] once per JSON-RPC call and once per request the access list refuses. Recording
  never fails the request it describes: errors are logged and swallowed."
  (:require
   [clojure.string :as str]
   [clojure.walk :as walk]
   [java-time.api :as t]
   [metabase.mcp-restrictions.core :as mcp-restrictions]
   [metabase.mcp-restrictions.settings :as mcp-restrictions.settings]
   [metabase.util.json :as json]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def statuses
  "The outcomes a recorded request can have."
  #{"success" "error" "denied"})

(def ^:private max-arguments-length 10000)
(def ^:private max-error-length 2000)
(def ^:private max-short-text-length 254)

(defn- truncate [s max-length]
  (when s
    (let [s (str s)]
      (if (> (count s) max-length)
        (str (subs s 0 (dec max-length)) "…")
        s))))

(defn- mask-secrets
  "Replace the value of every map entry whose key looks like it holds a secret (see
  [[mcp-restrictions/secret-name?]]), at any depth."
  [x]
  (walk/postwalk
   (fn [form]
     (if (map? form)
       (into (empty form)
             (map (fn [[k v]]
                    [k (if (and (or (keyword? k) (string? k))
                                (mcp-restrictions/secret-name? (name k)))
                         mcp-restrictions/masked-value
                         v)]))
             form)
       form))
   x))

(defn sanitize-arguments
  "JSON-encode request `arguments` for the audit log, with secret-looking keys masked and the result truncated. Returns
  nil when there are no arguments."
  [arguments]
  (when (and (some? arguments)
             (not (and (coll? arguments) (empty? arguments))))
    (truncate (json/encode (mask-secrets arguments)) max-arguments-length)))

(defn record!
  "Record one MCP request in the audit log. `entry` has `:user-id`, `:auth-method` (`:oauth` or `:session`),
  `:method` and `:status` (one of [[statuses]]), and optionally `:session-id`, `:target`, `:arguments` (any
  JSON-encodable value), `:error-message`, `:duration-ms`, `:ip-address` and `:user-agent`. No-op when the audit log
  is turned off. Never throws."
  [{:keys [user-id session-id auth-method method target arguments status error-message duration-ms ip-address
           user-agent]}]
  (when (mcp-restrictions.settings/mcp-audit-log-enabled?)
    (try
      (t2/insert! :model/McpAuditLog
                  {:user_id        user-id
                   :mcp_session_id (truncate session-id max-short-text-length)
                   :auth_method    (name (or auth-method :session))
                   :method         (truncate (or method "unknown") 64)
                   :target         (truncate target max-short-text-length)
                   :arguments      (sanitize-arguments arguments)
                   :status         status
                   :error_message  (truncate error-message max-error-length)
                   :duration_ms    (some-> duration-ms int)
                   :ip_address     (truncate ip-address 64)
                   :user_agent     (truncate user-agent max-short-text-length)})
      nil
      (catch Throwable e
        (log/warnf e "Failed to record MCP request %s in the audit log" method)
        nil))))

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

(defn distinct-methods
  "The JSON-RPC methods that appear in the audit log, for filtering."
  []
  (->> (t2/query {:select-distinct [:method] :from [:mcp_audit_log] :order-by [[:method :asc]]})
       (map :method)
       (remove str/blank?)
       vec))

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
