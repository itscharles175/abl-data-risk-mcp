import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import type {
  ModernCertificationDefinitionAuthorityV1 as PublicAuthority,
  ModernCertificationDefinitionResolutionV1 as PublicResolution,
  ModernDataQualityDefinitionV1 as PublicDataQuality,
  ModernReconciliationDefinitionV1 as PublicReconciliation
} from "../src/services/modern-snapshot-certification.js";
import type {
  ModernCertificationDefinitionAuthorityV1 as NeutralAuthority,
  ModernCertificationDefinitionResolutionV1 as NeutralResolution,
  ModernDataQualityDefinitionV1 as NeutralDataQuality,
  ModernReconciliationDefinitionV1 as NeutralReconciliation
} from "../src/services/modern-snapshot-certification-types-v1.js";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? (<Value>() => Value extends Right ? 1 : 2) extends
      (<Value>() => Value extends Left ? 1 : 2)
      ? true
      : false
    : false;

const compatibility: readonly [
  Equal<PublicAuthority, NeutralAuthority>,
  Equal<PublicResolution, NeutralResolution>,
  Equal<PublicDataQuality, NeutralDataQuality>,
  Equal<PublicReconciliation, NeutralReconciliation>
] = [true, true, true, true];

test("certification authority types remain exact public aliases across the neutral boundary", () => {
  assert.deepEqual(compatibility, [true, true, true, true]);
});

test("lifecycle certification depends on the neutral type boundary rather than the certification service", () => {
  const lifecycle = readFileSync(
    new URL("../src/control/lifecycle-snapshot-certification-definition-authority-v1.ts", import.meta.url),
    "utf8"
  );
  assert.match(lifecycle, /modern-snapshot-certification-types-v1\.js/u);
  assert.doesNotMatch(lifecycle, /from "\.\.\/services\/modern-snapshot-certification\.js"/u);
});
