"use strict";

(function attachResultIntro(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.IndustrySuiteResultIntro = api;
})(typeof globalThis === "undefined" ? this : globalThis, function createResultIntro() {
  function buildResultIntroText(data, item, recorded) {
    const sourceStatus = String(data.source_status || data.data_status || data.status || "");
    const datedPublic = sourceStatus.startsWith("VERIFIED");
    const example = sourceStatus.startsWith("EXAMPLE") || sourceStatus.startsWith("SYNTHETIC");
    const localInput = sourceStatus.startsWith("USER_SUPPLIED");
    const liveStatus = data.workbench_status && typeof data.workbench_status === "object"
      ? data.workbench_status
      : null;
    const sourceNote = example
      ? (item.slug === "chainwatch"
        ? "This watch-only calculation uses invented EVM observations. No live chain feed or company address is connected."
        : "This engineering example uses invented local input, not organization records.")
      : datedPublic
        ? (recorded
          ? "This dated result uses the public source linked below. Private organization records are not included."
          : "This result uses the public source linked below. Private organization records are not included.")
        : localInput
          ? "This result uses supplied local input; its source and authority need owner review."
          : sourceStatus.startsWith("DATA_UNAVAILABLE")
            ? "The live source did not return usable records for this run."
            : sourceStatus.startsWith("UNVERIFIED")
              ? "The source for this result could not be verified."
              : "No external source is connected to this result.";
    const modelNote = data.ai_output && data.ai_proof
      ? " A source-cited local model sample is included."
      : data.ai_invoked
        ? " A model call was reported, but no independent witness is attached here."
        : " This result was produced without a model call.";
    return [sourceNote + modelNote, liveStatus?.explanation].filter(Boolean).join(" ");
  }

  return Object.freeze({ buildResultIntroText });
});
