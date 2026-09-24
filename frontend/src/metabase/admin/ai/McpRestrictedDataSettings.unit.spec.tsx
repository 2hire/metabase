import userEvent from "@testing-library/user-event";

import {
  findRequests,
  setupDatabasesEndpoints,
  setupPropertiesEndpoints,
  setupSettingsEndpoints,
  setupTablesEndpoints,
  setupUpdateSettingEndpoint,
} from "__support__/server-mocks";
import { mockSettings } from "__support__/settings";
import { renderWithProviders, screen, waitFor } from "__support__/ui";
import { createMockState } from "metabase/redux/store/mocks";
import {
  createMockDatabase,
  createMockSettingDefinition,
  createMockSettings,
  createMockTable,
} from "metabase-types/api/mocks";

import { McpRestrictedDataSettings } from "./McpRestrictedDataSettings";

const WAREHOUSE = createMockDatabase({ id: 1, name: "Warehouse" });
const CRM = createMockDatabase({ id: 2, name: "CRM" });

const ORDERS = createMockTable({
  id: 10,
  db_id: 1,
  schema: "public",
  name: "orders",
});
const CUSTOMERS = createMockTable({
  id: 11,
  db_id: 2,
  schema: "sales",
  name: "customers",
});

const setup = async ({
  restrictedDatabaseIds = [],
  restrictedTableIds = [],
}: {
  restrictedDatabaseIds?: number[];
  restrictedTableIds?: number[];
} = {}) => {
  const settings = createMockSettings({
    "mcp-restricted-database-ids": restrictedDatabaseIds,
    "mcp-restricted-table-ids": restrictedTableIds,
  });

  setupPropertiesEndpoints(settings);
  setupSettingsEndpoints([
    createMockSettingDefinition({
      key: "mcp-restricted-database-ids",
      value: restrictedDatabaseIds,
    }),
    createMockSettingDefinition({
      key: "mcp-restricted-table-ids",
      value: restrictedTableIds,
    }),
  ]);
  setupUpdateSettingEndpoint();
  setupDatabasesEndpoints([WAREHOUSE, CRM], { hasSavedQuestions: false });
  setupTablesEndpoints([ORDERS, CUSTOMERS]);

  renderWithProviders(<McpRestrictedDataSettings />, {
    storeInitialState: createMockState({
      settings: mockSettings(settings),
    }),
  });

  await screen.findByText("Restricted data");
};

describe("McpRestrictedDataSettings", () => {
  it("shows the currently restricted databases and tables", async () => {
    await setup({ restrictedDatabaseIds: [2], restrictedTableIds: [10] });

    expect(await screen.findByText("CRM")).toBeInTheDocument();
    expect(await screen.findByText("public.orders")).toBeInTheDocument();
  });

  it("saves a newly restricted database", async () => {
    await setup({ restrictedDatabaseIds: [2] });

    await userEvent.click(screen.getByLabelText("Restricted databases"));
    await userEvent.click(
      await screen.findByRole("option", { name: "Warehouse" }),
    );

    await waitFor(async () => {
      const puts = await findRequests("PUT");
      expect(puts).toHaveLength(1);
    });
    const [put] = await findRequests("PUT");
    expect(put.url).toContain("/setting/mcp-restricted-database-ids");
    expect(put.body).toEqual({ value: [2, 1] });
  });

  it("groups tables by database and saves the selection", async () => {
    await setup();

    await userEvent.click(screen.getByLabelText("Restricted tables"));
    expect(await screen.findByText("Warehouse")).toBeInTheDocument();
    await userEvent.click(
      await screen.findByRole("option", { name: "sales.customers" }),
    );

    await waitFor(async () => {
      const puts = await findRequests("PUT");
      expect(puts).toHaveLength(1);
    });
    const [put] = await findRequests("PUT");
    expect(put.url).toContain("/setting/mcp-restricted-table-ids");
    expect(put.body).toEqual({ value: [11] });
  });
});
