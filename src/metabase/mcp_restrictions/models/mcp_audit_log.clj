(ns metabase.mcp-restrictions.models.mcp-audit-log
  "Append-only audit trail of the requests MCP clients make to the MCP server. See
  [[metabase.mcp-restrictions.audit-log]] for recording and reading it."
  (:require
   [methodical.core :as methodical]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(methodical/defmethod t2/table-name :model/McpAuditLog [_model] :mcp_audit_log)

(doto :model/McpAuditLog
  (derive :metabase/model))
