import type { DatabaseId } from "./database";
import type { FieldId } from "./field";
import type { PaginationRequest, PaginationResponse } from "./pagination";
import type { TableId } from "./table";

export type McpSensitiveFieldSource = "detected" | "manual" | "metadata";

export type McpFieldLocation = {
  id: FieldId;
  name: string;
  table_id: TableId;
  table_name: string | null;
  schema: string | null;
  database_id: DatabaseId | null;
  database_name: string | null;
};

export type McpSensitiveField = McpFieldLocation & {
  source: McpSensitiveFieldSource;
};

export type McpSensitiveFieldsResponse = {
  sensitive: McpSensitiveField[];
  excluded: McpFieldLocation[];
};

export type McpAuditLogStatus = "success" | "error" | "denied";

/** One request an MCP client made to the MCP server. */
export type McpAuditLogEntry = {
  id: number;
  created_at: string;
  user_id: number | null;
  mcp_session_id: string | null;
  auth_method: "oauth" | "session";
  /** JSON-RPC method, e.g. `tools/call`. */
  method: string;
  /** Tool name, resource URI or client name, depending on the method. */
  target: string | null;
  /** JSON-encoded arguments, with secrets masked; may be truncated. */
  arguments: string | null;
  status: McpAuditLogStatus;
  error_message: string | null;
  duration_ms: number | null;
  ip_address: string | null;
  user_agent: string | null;
  user_email: string | null;
  user_first_name: string | null;
  user_last_name: string | null;
};

export type ListMcpAuditLogRequest = {
  "user-id"?: number | null;
  method?: string | null;
  status?: McpAuditLogStatus | null;
} & PaginationRequest;

export type ListMcpAuditLogResponse = {
  data: McpAuditLogEntry[];
  /** The methods that appear in the log, for filtering. */
  methods: string[];
} & PaginationResponse;
