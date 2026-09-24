(ns metabase.mcp-restrictions.task.truncate-audit-log
  "Scheduled task that deletes MCP audit log entries older than the configured retention."
  (:require
   [clojurewerkz.quartzite.jobs :as jobs]
   [clojurewerkz.quartzite.schedule.cron :as cron]
   [clojurewerkz.quartzite.triggers :as triggers]
   [metabase.mcp-restrictions.audit-log :as audit-log]
   [metabase.task-history.core :as task-history]
   [metabase.task.core :as task]
   [metabase.util.log :as log]))

(set! *warn-on-reflection* true)

(defn- truncate-audit-log! []
  (task-history/with-task-history {:task "mcp-audit-log-cleanup"}
    (let [deleted (audit-log/delete-expired-entries!)]
      (log/infof "MCP audit log cleanup deleted %d rows" deleted))))

(task/defjob ^{:doc "Deletes MCP audit log entries older than the configured retention."} TruncateMcpAuditLog [_]
  (truncate-audit-log!))

(def ^:private job-key     "metabase.task.truncate-mcp-audit-log.job")
(def ^:private trigger-key "metabase.task.truncate-mcp-audit-log.trigger")
(def ^:private cron-schedule "0 30 3 * * ? *") ;; every day at 03:30

(defmethod task/init! ::TruncateMcpAuditLog [_]
  (let [job     (jobs/build
                 (jobs/of-type TruncateMcpAuditLog)
                 (jobs/with-identity (jobs/key job-key)))
        trigger (triggers/build
                 (triggers/with-identity (triggers/key trigger-key))
                 (triggers/start-now)
                 (triggers/with-schedule
                  (cron/schedule
                   (cron/cron-schedule cron-schedule)
                   (cron/with-misfire-handling-instruction-do-nothing))))]
    (task/schedule-task! job trigger)))
