/**
 * Deliberately small structural interfaces implemented by pg.Pool/PoolClient
 * and by conformance fakes. Shared repositories depend on this boundary rather
 * than constructing a network client or reading connection secrets.
 */
export interface PgQueryResult<Row extends object = Record<string, unknown>> {
  readonly rows: readonly Row[];
  readonly rowCount: number | null;
}

export interface PgQueryablePort {
  query<Row extends object = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[]
  ): Promise<PgQueryResult<Row>>;
}

export interface PgClientPort extends PgQueryablePort {
  release(error?: Error | boolean): void;
}

export interface PgPoolPort extends PgQueryablePort {
  connect(): Promise<PgClientPort>;
}

export type PgIsolationLevel = "read committed" | "repeatable read" | "serializable";

export async function withPgTransaction<T>(
  pool: PgPoolPort,
  isolation: PgIsolationLevel,
  operation: (client: PgClientPort) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  let failed: Error | undefined;
  try {
    await client.query(`BEGIN ISOLATION LEVEL ${isolation.toUpperCase()}`);
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    failed = error instanceof Error ? error : new Error("PostgreSQL transaction failed");
    try {
      await client.query("ROLLBACK");
    } catch {
      // Preserve the operation failure. The pg client is discarded below.
    }
    throw error;
  } finally {
    client.release(failed ?? false);
  }
}
