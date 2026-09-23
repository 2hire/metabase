import type { McpSensitiveFieldsResponse } from "metabase-types/api";

import { Api } from "./api";
import { tag } from "./tags";

export const mcpRestrictionsApi = Api.injectEndpoints({
  endpoints: (builder) => ({
    getMcpSensitiveFields: builder.query<McpSensitiveFieldsResponse, void>({
      query: () => ({
        method: "GET",
        url: "/api/mcp-restrictions/sensitive-fields",
      }),
      // The list is derived from settings, and updating any setting invalidates this tag.
      providesTags: [tag("session-properties")],
    }),
  }),
});

export const { useGetMcpSensitiveFieldsQuery } = mcpRestrictionsApi;
