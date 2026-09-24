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

/** The credential a recorded request authenticated with. */
export type McpAuditLogAuthMethod =
  | "session"
  | "api-key"
  | "oauth"
  | "mcp-ui"
  | "jwt";

/** One request an MCP client made to the MCP server. */
export type McpAuditLogEntry = {
  id: number;
  created_at: string;
  user_id: number | null;
  mcp_session_id: string | null;
  auth_method: McpAuditLogAuthMethod;
  /**
   * JSON-RPC method (e.g. `tools/call`), `other` for an unknown JSON-RPC method, or `http/<verb>` for a REST or
   * Agent API call an AI client made directly.
   */
  method: string;
  /**
   * Tool name, resource URI or client name depending on the JSON-RPC method, the raw method for `other`, or the
   * request URI for `http/<verb>`.
   */
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
  /** The methods an entry can have, for filtering. */
  methods: string[];
} & PaginationResponse;
