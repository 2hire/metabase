import userEvent from "@testing-library/user-event";

import {
  findRequests,
  setupGroupsEndpoint,
  setupPropertiesEndpoints,
  setupSettingsEndpoints,
  setupUpdateSettingEndpoint,
  setupUsersEndpoints,
} from "__support__/server-mocks";
import { mockSettings } from "__support__/settings";
import { renderWithProviders, screen, waitFor } from "__support__/ui";
import { createMockState } from "metabase/redux/store/mocks";
import {
  createMockGroup,
  createMockSettingDefinition,
  createMockSettings,
  createMockUserListResult,
} from "metabase-types/api/mocks";

import { McpAccessListSettings } from "./McpAccessListSettings";

const ALICE = createMockUserListResult({
  id: 1,
  common_name: "Alice Doe",
  email: "alice@example.com",
});
const BOB = createMockUserListResult({
  id: 2,
  common_name: "Bob Roe",
  email: "bob@example.com",
});
const DATA_TEAM = createMockGroup({ id: 5, name: "Data team" });

const setup = async ({
  allowedUserIds = [],
  allowedGroupIds = [],
}: {
  allowedUserIds?: number[];
  allowedGroupIds?: number[];
} = {}) => {
  const settings = createMockSettings({
    "mcp-allowed-user-ids": allowedUserIds,
    "mcp-allowed-group-ids": allowedGroupIds,
  });

  setupPropertiesEndpoints(settings);
  setupSettingsEndpoints([
    createMockSettingDefinition({
      key: "mcp-allowed-user-ids",
      value: allowedUserIds,
    }),
    createMockSettingDefinition({
      key: "mcp-allowed-group-ids",
      value: allowedGroupIds,
    }),
  ]);
  setupUpdateSettingEndpoint();
  setupUsersEndpoints([ALICE, BOB]);
  setupGroupsEndpoint([DATA_TEAM]);

  renderWithProviders(<McpAccessListSettings />, {
    storeInitialState: createMockState({
      settings: mockSettings(settings),
    }),
  });

  await screen.findByText("Access");
};

const findSettingPut = async () => {
  await waitFor(async () => {
    expect(await findRequests("PUT")).toHaveLength(1);
  });
  const [put] = await findRequests("PUT");
  return put;
};

describe("McpAccessListSettings", () => {
  it("shows the users and groups currently allowed", async () => {
    await setup({ allowedUserIds: [1], allowedGroupIds: [5] });

    expect(
      await screen.findByText("Alice Doe (alice@example.com)"),
    ).toBeInTheDocument();
    expect(await screen.findByText("Data team")).toBeInTheDocument();
  });

  it("adds a user to the access list", async () => {
    await setup({ allowedUserIds: [1] });

    await userEvent.click(screen.getByLabelText("Allowed users"));
    await userEvent.click(
      await screen.findByRole("option", {
        name: "Bob Roe (bob@example.com)",
      }),
    );

    const put = await findSettingPut();
    expect(put.url).toContain("/setting/mcp-allowed-user-ids");
    expect(put.body).toEqual({ value: [1, 2] });
  });

  it("adds a group to the access list", async () => {
    await setup();

    await userEvent.click(screen.getByLabelText("Allowed groups"));
    await userEvent.click(
      await screen.findByRole("option", { name: "Data team" }),
    );

    const put = await findSettingPut();
    expect(put.url).toContain("/setting/mcp-allowed-group-ids");
    expect(put.body).toEqual({ value: [5] });
  });
});
