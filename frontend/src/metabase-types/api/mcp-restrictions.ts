import type { DatabaseId } from "./database";
import type { FieldId } from "./field";
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
