import userEvent from "@testing-library/user-event";
import fetchMock from "fetch-mock";

import {
  findRequests,
  setupDatabasesEndpoints,
  setupPropertiesEndpoints,
  setupSettingsEndpoints,
  setupTableQueryMetadataEndpoint,
  setupTablesEndpoints,
  setupUpdateSettingEndpoint,
  setupUpdateSettingsEndpoint,
} from "__support__/server-mocks";
import { mockSettings } from "__support__/settings";
import { renderWithProviders, screen, waitFor } from "__support__/ui";
import { createMockState } from "metabase/redux/store/mocks";
import type { McpSensitiveFieldsResponse } from "metabase-types/api";
import {
  createMockDatabase,
  createMockField,
  createMockSettingDefinition,
  createMockSettings,
  createMockTable,
} from "metabase-types/api/mocks";

import { McpSensitiveFieldsSettings } from "./McpSensitiveFieldsSettings";

const DATABASE = createMockDatabase({ id: 1, name: "Warehouse" });
const ACCOUNTS = createMockTable({
  id: 10,
  db_id: 1,
  schema: "public",
  name: "accounts",
  fields: [
    createMockField({ id: 100, table_id: 10, name: "client_id" }),
    createMockField({ id: 101, table_id: 10, name: "client_secret" }),
    createMockField({ id: 102, table_id: 10, name: "notes" }),
  ],
});

const LOCATION = {
  table_id: 10,
  table_name: "accounts",
  schema: "public",
  database_id: 1,
  database_name: "Warehouse",
};

const setup = async ({
  manualIds = [],
  excludedIds = [],
  response = { sensitive: [], excluded: [] },
}: {
  manualIds?: number[];
  excludedIds?: number[];
  response?: McpSensitiveFieldsResponse;
} = {}) => {
  const settings = createMockSettings({
    "mcp-sensitive-fields-auto-detect": true,
    "mcp-sensitive-field-ids": manualIds,
    "mcp-non-sensitive-field-ids": excludedIds,
  });

  setupPropertiesEndpoints(settings);
  setupSettingsEndpoints([
    createMockSettingDefinition({
      key: "mcp-sensitive-fields-auto-detect",
      value: true,
    }),
    createMockSettingDefinition({
      key: "mcp-sensitive-field-ids",
      value: manualIds,
    }),
    createMockSettingDefinition({
      key: "mcp-non-sensitive-field-ids",
      value: excludedIds,
    }),
  ]);
  setupUpdateSettingEndpoint();
  setupUpdateSettingsEndpoint();
  setupDatabasesEndpoints([DATABASE], { hasSavedQuestions: false });
  setupTablesEndpoints([ACCOUNTS]);
  setupTableQueryMetadataEndpoint(ACCOUNTS);
  fetchMock.get("path:/api/mcp-restrictions/sensitive-fields", response);

  renderWithProviders(<McpSensitiveFieldsSettings />, {
    storeInitialState: createMockState({
      settings: mockSettings(settings),
    }),
  });

  await screen.findByText("Sensitive fields");
};

const findPut = async () => {
  await waitFor(async () => {
    expect(await findRequests("PUT")).toHaveLength(1);
  });
  const [put] = await findRequests("PUT");
  return put;
};

describe("McpSensitiveFieldsSettings", () => {
  it("lists the sensitive fields with why they are sensitive", async () => {
    await setup({
      response: {
        sensitive: [
          { ...LOCATION, id: 101, name: "client_secret", source: "detected" },
        ],
        excluded: [],
      },
    });

    expect(
      await screen.findByText("Warehouse › public.accounts.client_secret"),
    ).toBeInTheDocument();
    expect(screen.getByText("Detected by name")).toBeInTheDocument();
  });

  it("stops treating a detected field as sensitive by excluding it", async () => {
    await setup({
      response: {
        sensitive: [
          { ...LOCATION, id: 101, name: "client_secret", source: "detected" },
        ],
        excluded: [],
      },
    });

    await userEvent.click(
      await screen.findByRole("button", {
        name: "Stop treating client_secret as sensitive",
      }),
    );

    const put = await findPut();
    expect(put.url).toMatch(/\/api\/setting$/);
    expect(put.body).toEqual({
      "mcp-sensitive-field-ids": [],
      "mcp-non-sensitive-field-ids": [101],
    });
  });

  it("adds a field picked from a table", async () => {
    await setup({ excludedIds: [102] });

    await userEvent.click(screen.getByLabelText("Table"));
    await userEvent.click(
      await screen.findByRole("option", { name: "public.accounts" }),
    );
    await userEvent.click(screen.getByLabelText("Field"));
    await userEvent.click(await screen.findByRole("option", { name: "notes" }));
    await userEvent.click(screen.getByRole("button", { name: "Add" }));

    const put = await findPut();
    expect(put.body).toEqual({
      "mcp-sensitive-field-ids": [102],
      "mcp-non-sensitive-field-ids": [],
    });
  });

  it("restores an excluded field", async () => {
    await setup({
      excludedIds: [100, 102],
      response: {
        sensitive: [],
        excluded: [{ ...LOCATION, id: 102, name: "notes" }],
      },
    });

    await userEvent.click(
      await screen.findByRole("button", { name: "Restore notes" }),
    );

    const put = await findPut();
    expect(put.url).toMatch(/\/api\/setting$/);
    expect(put.body).toEqual({
      "mcp-sensitive-field-ids": [],
      "mcp-non-sensitive-field-ids": [100],
    });
  });

  it("can turn off detection by name", async () => {
    await setup();

    await userEvent.click(
      screen.getByRole("switch", { name: /Detect sensitive fields by name/ }),
    );

    const put = await findPut();
    expect(put.url).toContain("/setting/mcp-sensitive-fields-auto-detect");
    expect(put.body).toEqual({ value: false });
  });
});
