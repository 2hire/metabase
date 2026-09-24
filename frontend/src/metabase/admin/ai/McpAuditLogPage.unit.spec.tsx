import type { Row, Table } from "@tanstack/react-table";
import userEvent from "@testing-library/user-event";
import fetchMock from "fetch-mock";
import type { KeyboardEvent, ReactNode } from "react";
import { Route } from "react-router";

import {
  setupMcpAuditLogEndpoint,
  setupUsersEndpoints,
} from "__support__/server-mocks";
import { renderWithProviders, screen, waitFor, within } from "__support__/ui";
import type {
  ListMcpAuditLogResponse,
  McpAuditLogEntry,
  UserListResult,
} from "metabase-types/api";
import {
  createMockListMcpAuditLogResponse,
  createMockMcpAuditLogEntry,
  createMockUser,
} from "metabase-types/api/mocks";

import { MCP_AUDIT_LOG_PAGE_SIZE, McpAuditLogPage } from "./McpAuditLogPage";

// TreeTable virtualizes its rows, which renders nothing in jsdom. Mock it to
// render each row's cells via flexRender so the column cell logic is exercised,
// and to forward key presses to the instance's keyboard handler like the real one.
jest.mock("metabase/ui/components/data-display/TreeTable/TreeTable", () => {
  const { flexRender } = jest.requireActual("@tanstack/react-table");
  return {
    TreeTable: ({
      instance,
      emptyState,
      ariaLabel,
      onRowClick,
    }: {
      instance: {
        table: Table<McpAuditLogEntry>;
        handleKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
      };
      emptyState: ReactNode;
      ariaLabel?: string;
      onRowClick?: (row: Row<McpAuditLogEntry>) => void;
    }) => {
      const rows = instance.table.getRowModel().rows;
      if (rows.length === 0) {
        return <div>{emptyState}</div>;
      }
      return (
        <div
          role="treegrid"
          tabIndex={0}
          aria-label={ariaLabel}
          onKeyDown={instance.handleKeyDown}
        >
          {rows.map((row) => (
            <div key={row.id} role="row" onClick={() => onRowClick?.(row)}>
              {row.getVisibleCells().map((cell) => (
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
  users = [createMockUser()],
}: {
  response?: ListMcpAuditLogResponse;
  error?: boolean;
  users?: UserListResult[];
} = {}) => {
  if (error) {
    fetchMock.get("path:/api/mcp-restrictions/audit-log", { status: 500 });
  } else {
    setupMcpAuditLogEndpoint(response);
  }
  setupUsersEndpoints(users);

  return renderWithProviders(
    <Route path={PATHNAME} component={McpAuditLogPage} />,
    { withRouter: true, initialRoute: PATHNAME },
  );
};

const lastUsersCallUrl = () => {
  const calls = fetchMock.callHistory.calls("path:/api/user");
  return calls[calls.length - 1]?.url ?? "";
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

  it("doesn't crash when a logged method looks like the filters' sentinel value", async () => {
    setup({
      response: createMockListMcpAuditLogResponse({
        methods: ["all", "tools/call", "tools/call"],
      }),
    });

    await screen.findByTestId("mcp-audit-log-table");
    await userEvent.click(screen.getByLabelText("Filter by method"));
    expect(
      await screen.findByRole("option", { name: "All methods" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("option", { name: "tools/call" })).toHaveLength(
      1,
    );
    await userEvent.click(screen.getByRole("option", { name: "all" }));

    await waitFor(() => {
      expect(lastCallUrl()).toContain("method=all");
    });
  });

  it.each([
    ["session", "Session"],
    ["api-key", "API key"],
    ["oauth", "OAuth token"],
    ["mcp-ui", "MCP Apps iframe"],
  ] as const)(
    "shows the %s authentication method in the details",
    async (authMethod, label) => {
      setup({
        response: createMockListMcpAuditLogResponse({
          data: [createMockMcpAuditLogEntry({ auth_method: authMethod })],
        }),
      });

      await userEvent.click(await screen.findByRole("row"));

      const details = await screen.findByTestId("mcp-audit-log-details");
      expect(within(details).getByText(label)).toBeInTheDocument();
    },
  );

  it("opens the details of a request from the keyboard", async () => {
    setup({
      response: createMockListMcpAuditLogResponse({
        data: [
          createMockMcpAuditLogEntry({
            status: "error",
            error_message: "Unknown tool: nope",
          }),
        ],
      }),
    });

    const grid = await screen.findByRole("treegrid", {
      name: "MCP audit log",
    });
    grid.focus();
    await userEvent.keyboard("{ArrowDown}{Enter}");

    const details = await screen.findByTestId("mcp-audit-log-details");
    expect(within(details).getByText("Unknown tool: nope")).toBeInTheDocument();
  });

  it("offers deactivated users in the user filter", async () => {
    setup({
      users: [
        createMockUser({
          id: 1,
          common_name: "Active Person",
          email: "active@example.com",
        }),
        createMockUser({
          id: 2,
          common_name: "Gone Person",
          email: "gone@example.com",
          is_active: false,
        }),
      ],
    });

    await screen.findByTestId("mcp-audit-log-table");
    await waitFor(() => {
      expect(lastUsersCallUrl()).toContain("status=all");
    });
    await userEvent.click(screen.getByLabelText("Filter by user"));
    await userEvent.click(
      await screen.findByRole("option", {
        name: "Gone Person (gone@example.com) (deactivated)",
      }),
    );

    await waitFor(() => {
      expect(lastCallUrl()).toContain("user-id=2");
    });
  });
});
