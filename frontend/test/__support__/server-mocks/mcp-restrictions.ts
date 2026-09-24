import fetchMock, { type UserRouteConfig } from "fetch-mock";

import type { ListMcpAuditLogResponse } from "metabase-types/api";

export function setupMcpAuditLogEndpoint(
  response: ListMcpAuditLogResponse,
  options?: UserRouteConfig,
) {
  fetchMock.get("path:/api/mcp-restrictions/audit-log", response, options);
}
