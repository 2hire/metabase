import userEvent from "@testing-library/user-event";
import fetchMock from "fetch-mock";
import type { ReactNode } from "react";
import { Route } from "react-router";

import {
  setupMcpAuditLogEndpoint,
  setupUsersEndpoints,
} from "__support__/server-mocks";
import { renderWithProviders, screen, waitFor, within } from "__support__/ui";
import type { ListMcpAuditLogResponse } from "metabase-types/api";
import {
  createMockListMcpAuditLogResponse,
  createMockMcpAuditLogEntry,
  createMockUserListResult,
} from "metabase-types/api/mocks";

import { MCP_AUDIT_LOG_PAGE_SIZE, McpAuditLogPage } from "./McpAuditLogPage";

// TreeTable virtualizes its rows, which renders nothing in jsdom. Mock it to
// render each row's cells via flexRender so the column cell logic is exercised.
jest.mock("metabase/ui/components/data-display/TreeTable/TreeTable", () => {
  const { flexRender } = jest.requireActual("@tanstack/react-table");
  return {
    TreeTable: ({
      instance,
      emptyState,
      onRowClick,
    }: {
      instance: { table: { getRowModel: () => { rows: any[] } } };
      emptyState: ReactNode;
      onRowClick?: (row: any) => void;
    }) => {
      const rows = instance.table.getRowModel().rows;
      if (rows.length === 0) {
        return <div>{emptyState}</div>;
      }
      return (
        <div>
          {rows.map((row) => (
            <div key={row.id} role="row" onClick={() => onRowClick?.(row)}>
              {row.getVisibleCells().map((cell: any) => (
                <span key={cell.id}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </span>
              ))}
            </div>
          ))}
        </div>
      );
    },
  };
});

const PATHNAME = "/admin/metabot/mcp/audit-log";

const setup = ({
  response = createMockListMcpAuditLogResponse(),
  error = false,
}: {
  response?: ListMcpAuditLogResponse;
  error?: boolean;
} = {}) => {
  if (error) {
    fetchMock.get("path:/api/mcp-restrictions/audit-log", { status: 500 });
  } else {
    setupMcpAuditLogEndpoint(response);
  }
  setupUsersEndpoints([createMockUserListResult()]);

  return renderWithProviders(
    <Route path={PATHNAME} component={McpAuditLogPage} />,
    { withRouter: true, initialRoute: PATHNAME },
  );
};

const lastCallUrl = () => {
  const calls = fetchMock.callHistory.calls(
    "path:/api/mcp-restrictions/audit-log",
  );
  return calls[calls.length - 1]?.url ?? "";
};

describe("McpAuditLogPage", () => {
  it("shows an empty state when there are no requests", async () => {
    setup({
      response: createMockListMcpAuditLogResponse({ data: [], total: 0 }),
    });

    expect(
      await screen.findByTestId("mcp-audit-log-empty"),
    ).toBeInTheDocument();
  });

  it("renders a row per request with user, method, tool, outcome and duration", async () => {
    setup({
      response: createMockListMcpAuditLogResponse({
        data: [
          createMockMcpAuditLogEntry({
            user_email: "user@example.com",
            method: "tools/call",
            target: "execute_query",
            status: "error",
            duration_ms: 42,
          }),
        ],
      }),
    });

    const table = await screen.findByTestId("mcp-audit-log-table");
    expect(within(table).getByText("user@example.com")).toBeInTheDocument();
    expect(within(table).getByText("tools/call")).toBeInTheDocument();
    expect(within(table).getByText("execute_query")).toBeInTheDocument();
    expect(within(table).getByText("Error")).toBeInTheDocument();
    expect(within(table).getByText("42 ms")).toBeInTheDocument();
  });

  it("shows the arguments and the error of a request when its row is clicked", async () => {
    setup({
      response: createMockListMcpAuditLogResponse({
        data: [
          createMockMcpAuditLogEntry({
            arguments: '{"query":"revenue"}',
            status: "error",
            error_message: "Unknown tool: nope",
          }),
        ],
      }),
    });

    await userEvent.click(await screen.findByRole("row"));

    const details = await screen.findByTestId("mcp-audit-log-details");
    expect(within(details).getByText("Unknown tool: nope")).toBeInTheDocument();
    expect(within(details).getByText(/"query": "revenue"/)).toBeInTheDocument();
  });

  it("requests the first page without filters by default", async () => {
    setup();

    await waitFor(() => {
      expect(lastCallUrl()).toContain(`limit=${MCP_AUDIT_LOG_PAGE_SIZE}`);
    });
    expect(lastCallUrl()).toContain("offset=0");
    expect(lastCallUrl()).not.toContain("status=");
    expect(lastCallUrl()).not.toContain("method=");
  });

  it("refetches with the selected outcome when the filter changes", async () => {
    setup();

    await screen.findByTestId("mcp-audit-log-table");
    await userEvent.click(screen.getByLabelText("Filter by outcome"));
    await userEvent.click(
      await screen.findByRole("option", { name: "Denied" }),
    );

    await waitFor(() => {
      expect(lastCallUrl()).toContain("status=denied");
    });
  });

  it("offers the methods found in the log as filters", async () => {
    setup();

    await screen.findByTestId("mcp-audit-log-table");
    await userEvent.click(screen.getByLabelText("Filter by method"));
    await userEvent.click(
      await screen.findByRole("option", { name: "tools/list" }),
    );

    await waitFor(() => {
      expect(lastCallUrl()).toContain("method=tools%2Flist");
    });
  });
});
