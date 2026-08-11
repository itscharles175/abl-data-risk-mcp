import type { AppConfig, SourceConfig } from "../../config.js";
import { PostgresAdapter } from "./postgres.js";
import { SqliteAdapter } from "./sqlite.js";
import type { SqlAdapter } from "./types.js";

export interface PublicSourceInfo {
  readonly id: string;
  readonly dialect: SourceConfig["dialect"];
  readonly allowedSchemas: readonly string[];
  readonly allowedTables: readonly string[];
}

export class SourceRegistry {
  readonly #configs: ReadonlyMap<string, SourceConfig>;
  readonly #adapters = new Map<string, SqlAdapter>();

  constructor(config: AppConfig) {
    this.#configs = new Map(config.sources.map((source) => [source.id, source]));
  }

  listSources(): readonly PublicSourceInfo[] {
    return [...this.#configs.values()]
      .map((source) => ({
        id: source.id,
        dialect: source.dialect,
        allowedSchemas: [...source.allowedSchemas],
        allowedTables: [...source.allowedTables]
      }))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  get(sourceId: string): SqlAdapter {
    const existing = this.#adapters.get(sourceId);
    if (existing) return existing;

    const config = this.#configs.get(sourceId);
    if (!config) throw new Error(`Unknown source id: ${sourceId}`);

    const adapter: SqlAdapter =
      config.dialect === "postgres" ? new PostgresAdapter(config) : new SqliteAdapter(config);
    this.#adapters.set(sourceId, adapter);
    return adapter;
  }

  async close(): Promise<void> {
    await Promise.all([...this.#adapters.values()].map((adapter) => adapter.close()));
    this.#adapters.clear();
  }
}
