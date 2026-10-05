"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildResultIntroText } = require("../webapp/static/result-intro.js");

const ledgerbridge = { slug: "ledgerbridge" };

function noModelReceipt(status, explanation) {
  return {
    source_status: status,
    workflow_status: "UNVERIFIED",
    task_result: null,
    evidence: [],
    ai_invoked: false,
    workbench_status: { label: status, tone: "warn", explanation },
  };
}

test("DATA_UNAVAILABLE intro describes the attempted live source without contradiction", () => {
  const text = buildResultIntroText(
    noModelReceipt(
      "DATA_UNAVAILABLE",
      "The live source did not return usable records for this run. No fixture, cache, or substitute was used; retry the same source later. The full workflow remains unverified.",
    ),
    ledgerbridge,
    false,
  );

  assert.match(text, /The live source did not return usable records for this run\./);
  assert.doesNotMatch(text, /No external source is connected to this result\./);
  assert.match(text, /No fixture, cache, or substitute was used/);
  assert.match(text, /full workflow remains unverified/i);
  assert.match(text, /without a model call/);
});

test("UNVERIFIED intro identifies uncertainty without claiming no source is connected", () => {
  const text = buildResultIntroText(
    noModelReceipt(
      "UNVERIFIED",
      "Source provenance, terms, freshness, task fit, or authority could not be established. No records are treated as verified, and no substitute was used.",
    ),
    ledgerbridge,
    false,
  );

  assert.match(text, /source for this result could not be verified/i);
  assert.doesNotMatch(text, /No external source is connected to this result\./);
  assert.match(text, /No records are treated as verified/);
  assert.match(text, /no substitute was used/i);
  assert.match(text, /without a model call/);
});

test("source-less synthetic ChainWatch example keeps its existing disclosure", () => {
  const text = buildResultIntroText(
    {
      source_status: "SYNTHETIC / ENGINEERING ONLY",
      ai_invoked: false,
      workbench_status: { label: "LABELLED EXAMPLE", explanation: "Synthetic example only." },
    },
    { slug: "chainwatch" },
    false,
  );

  assert.match(text, /invented EVM observations/);
  assert.match(text, /No live chain feed or company address is connected/);
  assert.doesNotMatch(text, /live source did not return usable records/i);
  assert.doesNotMatch(text, /No external source is connected to this result\./);
});

test("a receipt with no declared source status keeps the no-source fallback", () => {
  const text = buildResultIntroText({ ai_invoked: false }, ledgerbridge, false);

  assert.match(text, /^No external source is connected to this result\./);
  assert.match(text, /without a model call/);
});
