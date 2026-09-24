import type {
  ListMcpAuditLogResponse,
  McpAuditLogEntry,
} from "metabase-types/api";

export const createMockMcpAuditLogEntry = (
  opts?: Partial<McpAuditLogEntry>,
): McpAuditLogEntry => ({
  id: 1,
  created_at: "2026-09-24T10:00:00Z",
  user_id: 3,
  mcp_session_id: "8f1b2c3d-0000-4a5b-8c9d-000000000001",
  auth_method: "oauth",
  method: "tools/call",
  target: "execute_query",
  arguments: '{"query":"revenue"}',
  status: "success",
  error_message: null,
  duration_ms: 42,
  ip_address: "127.0.0.1",
  user_agent: "claude-code/1.0",
  user_email: "user@example.com",
  user_first_name: "Test",
  user_last_name: "User",
  ...opts,
});

export const createMockListMcpAuditLogResponse = (
  opts?: Partial<ListMcpAuditLogResponse>,
): ListMcpAuditLogResponse => ({
  data: [createMockMcpAuditLogEntry()],
  methods: ["initialize", "tools/call", "tools/list"],
  total: 1,
  limit: 50,
  offset: 0,
  ...opts,
});
