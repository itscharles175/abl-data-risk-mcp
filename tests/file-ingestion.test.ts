import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { loadLoanTapeFile, LoanTapeFileError } from "../src/services/file-ingestion.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

test("CSV loader preserves exact values and RFC 4180 quoting", () => {
  const directory = temporaryDirectory();
  const path = join(directory, "loan-tape.csv");
  writeFileSync(
    path,
    '\ufeffloan_id,as_of_date,balance,note\r\nL-1,2026-07-31,1000000000000000000.01,"line one, ""quoted"""\r\n',
    "utf8"
  );
  const loaded = loadLoanTapeFile(path);
  assert.equal(loaded.format, "csv");
  assert.equal(loaded.byteLength > 0, true);
  assert.match(loaded.sourceHash, /^[a-f0-9]{64}$/);
  assert.deepEqual(loaded.columns, ["as_of_date", "balance", "loan_id", "note"]);
  assert.deepEqual(loaded.records, [
    { loan_id: "L-1", as_of_date: "2026-07-31", balance: "1000000000000000000.01", note: 'line one, "quoted"' }
  ]);
});

test("JSON and NDJSON loaders require exact decimal text and scalar cells", () => {
  const directory = temporaryDirectory();
  const jsonPath = join(directory, "loan-tape.json");
  writeFileSync(jsonPath, JSON.stringify([{ loan_id: "L-1", balance: "10.25", active: true, sequence: 1 }]), "utf8");
  assert.deepEqual(loadLoanTapeFile(jsonPath).records[0], {
    loan_id: "L-1",
    balance: "10.25",
    active: true,
    sequence: 1
  });

  const ndjsonPath = join(directory, "loan-tape.ndjson");
  writeFileSync(ndjsonPath, '{"loan_id":"L-1","balance":"1"}\n\n{"loan_id":"L-2","balance":"2"}\n', "utf8");
  assert.equal(loadLoanTapeFile(ndjsonPath).records.length, 2);

  writeFileSync(jsonPath, '[{"balance":10.25}]', "utf8");
  assert.throws(
    () => loadLoanTapeFile(jsonPath),
    (error: unknown) => error instanceof LoanTapeFileError && error.code === "INVALID_DOCUMENT"
  );
  writeFileSync(jsonPath, '[{"nested":{"secret":"value"}}]', "utf8");
  assert.throws(() => loadLoanTapeFile(jsonPath), LoanTapeFileError);
});

test("loader fails closed on malformed CSV, symlinks, and configured bounds", () => {
  const directory = temporaryDirectory();
  const malformed = join(directory, "malformed.csv");
  writeFileSync(malformed, 'a,b\n"unterminated,b\n', "utf8");
  assert.throws(
    () => loadLoanTapeFile(malformed),
    (error: unknown) => error instanceof LoanTapeFileError && error.code === "INVALID_DOCUMENT"
  );

  const bounded = join(directory, "bounded.csv");
  writeFileSync(bounded, "a,b\n1,2\n3,4\n", "utf8");
  if (process.platform !== "win32") {
    const linked = join(directory, "linked.csv");
    symlinkSync(bounded, linked);
    assert.throws(
      () => loadLoanTapeFile(linked),
      (error: unknown) => error instanceof LoanTapeFileError && error.code === "INVALID_INPUT"
    );
  }
  assert.throws(
    () => loadLoanTapeFile(bounded, { maximumRecords: 1 }),
    (error: unknown) => error instanceof LoanTapeFileError && error.code === "LIMIT_EXCEEDED"
  );
  assert.throws(
    () => loadLoanTapeFile(bounded, { maximumColumns: 1 }),
    (error: unknown) => error instanceof LoanTapeFileError && error.code === "LIMIT_EXCEEDED"
  );
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "abl-file-ingestion-"));
  directories.push(directory);
  return directory;
}
