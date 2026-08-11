import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";

import * as z from "zod/v4";

const sourceId = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_-]*$/, "must start with a letter and contain only lowercase letters, digits, _ or -");

const commonSource = z.object({
  id: sourceId,
  allowedSchemas: z.array(z.string().min(1).max(128)).min(1),
  allowedTables: z.array(z.string().min(1).max(257)).min(1),
  restrictedColumns: z.array(z.string().min(1).max(128)).default([]),
  statementTimeoutMs: z.number().int().min(100).max(60_000).default(15_000),
  maxResultRows: z.number().int().min(1).max(5_000).default(500)
}).strict();

const postgresSource = commonSource.extend({
  dialect: z.literal("postgres"),
  connectionEnv: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Z][A-Z0-9_]*$/, "must be an environment variable name")
});

const sqliteSource = commonSource.extend({
  dialect: z.literal("sqlite"),
  path: z.string().min(1).max(4096)
});

export const sourceConfigSchema = z.discriminatedUnion("dialect", [postgresSource, sqliteSource]);

const appConfigSchema = z
  .object({
    sources: z.array(sourceConfigSchema).default([]),
    analysis: z
      .object({
        maxGroups: z.number().int().min(1).max(1_000).default(200),
        maxVintagePoints: z.number().int().min(1).max(25_000).default(5_000),
        minimumCohortSize: z.number().int().min(1).max(1_000).default(10)
      })
      .strict()
      .default({ maxGroups: 200, maxVintagePoints: 5_000, minimumCohortSize: 10 })
  })
  .strict()
  .superRefine((config, context) => {
    const seen = new Set<string>();
    for (const source of config.sources) {
      if (seen.has(source.id)) {
        context.addIssue({
          code: "custom",
          message: `duplicate source id: ${source.id}`,
          path: ["sources"]
        });
      }
      seen.add(source.id);
    }
  });

export type SourceConfig = z.infer<typeof sourceConfigSchema>;
export type PostgresSourceConfig = Extract<SourceConfig, { dialect: "postgres" }>;
export type SqliteSourceConfig = Extract<SourceConfig, { dialect: "sqlite" }>;
export type AppConfig = z.infer<typeof appConfigSchema>;

const EMPTY_CONFIG: AppConfig = appConfigSchema.parse({});

export function loadConfig(explicitPath?: string): AppConfig {
  const configuredPath = explicitPath ?? process.env.ABL_MCP_CONFIG;
  if (!configuredPath) return EMPTY_CONFIG;

  const absolutePath = resolve(configuredPath);
  if (!existsSync(absolutePath)) {
    throw new Error(`ABL MCP configuration does not exist: ${absolutePath}`);
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(readFileSync(absolutePath, "utf8"));
  } catch (error) {
    throw new Error(`ABL MCP configuration is not valid JSON: ${absolutePath}`, { cause: error });
  }

  const config = appConfigSchema.parse(parsedJson);
  const configDirectory = dirname(absolutePath);

  return {
    ...config,
    sources: config.sources.map((source) => {
      if (source.dialect !== "sqlite" || isAbsolute(source.path)) return source;
      return { ...source, path: resolve(configDirectory, source.path) };
    })
  };
}
