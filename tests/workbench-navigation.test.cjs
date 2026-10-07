"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync(require.resolve("../webapp/static/app.js"), "utf8");
const bootstrap = 'renderNav();select(location.hash.slice(1));window.addEventListener("hashchange",()=>select(location.hash.slice(1)));$("run-form").addEventListener("submit",submit);$("download-button").addEventListener("click",download);$("review-button").addEventListener("click",review);';
assert.ok(source.includes(bootstrap), "the workbench bootstrap should remain identifiable");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function element() {
  const listeners = new Map();
  return {
    id: "",
    textContent: "",
    disabled: false,
    hidden: false,
    children: [],
    dataset: {},
    files: [],
    append(...children) {
      children.forEach((child) => { child.parentElement = this; });
      this.children.push(...children);
    },
    replaceChildren(...children) {
      this.children.forEach((child) => { child.parentElement = null; });
      this.children = [];
      this.append(...children);
    },
    addEventListener(type, listener) {
      const callbacks = listeners.get(type) || [];
      callbacks.push(listener);
      listeners.set(type, callbacks);
    },
    dispatch(type, event = {}) {
      return (listeners.get(type) || []).map((listener) => listener({ target: this, currentTarget: this, ...event }));
    },
    click() { return this.dispatch("click")[0]; },
    setAttribute() {},
    removeAttribute() {},
  };
}

function makeWorkbench(requests) {
  const elements = new Map();
  const allElements = [];
  const rendered = [];
  const errors = [];
  function createElement(tag) {
    const node = element();
    node.tagName = tag;
    allElements.push(node);
    return node;
  }
  const document = {
    documentElement: { dataset: { mode: "local" } },
    querySelector() { return { content: "test-token" }; },
    querySelectorAll() { return []; },
    getElementById(id) {
      if (!elements.has(id)) {
        const node = element();
        node.id = id;
        elements.set(id, node);
        allElements.push(node);
      }
      return elements.get(id);
    },
    createElement,
  };
  const context = vm.createContext({
    document,
    window: { addEventListener() {} },
    location: { hash: "" },
    history: { replaceState() {} },
    fetch: () => requests.shift().promise,
    console,
  });
  vm.runInContext(source.replace(bootstrap, ""), context, { filename: "webapp/static/app.js" });
  context.setCopy = () => {};
  context.setState = () => {};
  context.payloadFor = () => ({ mode: "public" });
  context.renderResult = (data) => {
    rendered.push({ workflow: vm.runInContext("current.slug", context), data });
  };
  context.showError = (message) => { errors.push(message); };
  context.select("ledgerbridge");
  return {
    context,
    elements,
    errors,
    rendered,
    byId(id) { return allElements.find((node) => node.id === id); },
    byText(text) { return allElements.find((node) => node.textContent === text); },
  };
}

function response(data, ok = true) {
  return { ok, json: async () => data };
}

test("changing workflows makes the Run button available while the old request is pending", async () => {
  const first = deferred();
  const { context, elements } = makeWorkbench([first]);
  const pending = context.submit({ preventDefault() {} });
  context.select("marketbrief");
  const disabledAfterNavigation = elements.get("run-button").disabled;
  first.resolve(response({ old: true }));
  await pending;

  assert.equal(disabledAfterNavigation, false, "a pending request for the previous workflow must not lock the selected workflow");
});

test("a response from before leaving and returning to the same workflow is ignored", async () => {
  const first = deferred();
  const latest = deferred();
  const { context, elements, rendered } = makeWorkbench([first, latest]);
  const earlierRun = context.submit({ preventDefault() {} });
  context.select("marketbrief");
  context.select("ledgerbridge");
  const latestRun = context.submit({ preventDefault() {} });

  first.resolve(response({ old: true }));
  await earlierRun;
  assert.equal(elements.get("run-button").disabled, true, "the earlier request must not unlock the newer run");
  assert.deepEqual(rendered, [], "the newly selected view must not be replaced by its earlier request");

  latest.resolve(response({ new: true }));
  await latestRun;
  assert.deepEqual(rendered, [{ workflow: "ledgerbridge", data: { new: true } }]);
});

test("an earlier workflow request cannot unlock a later workflow while it is running", async () => {
  const earlier = deferred();
  const current = deferred();
  const { context, elements, rendered } = makeWorkbench([earlier, current]);
  const earlierRun = context.submit({ preventDefault() {} });
  context.select("marketbrief");
  const currentRun = context.submit({ preventDefault() {} });

  earlier.resolve(response({ old: true }));
  await earlierRun;
  assert.equal(elements.get("run-button").disabled, true, "the selected workflow stays busy until its own request finishes");
  assert.deepEqual(rendered, []);

  current.resolve(response({ new: true }));
  await currentRun;
  assert.equal(elements.get("run-button").disabled, false);
  assert.deepEqual(rendered, [{ workflow: "marketbrief", data: { new: true } }]);
});

test("a safe-example failure from before leaving and returning does not replace the selected view", async () => {
  const example = deferred();
  const workbench = makeWorkbench([example]);
  const route = workbench.byId("input-route");
  route.value = "enterprise";
  route.dispatch("change");
  const pending = workbench.byText("Load safe example").click();

  workbench.context.select("marketbrief");
  workbench.context.select("ledgerbridge");
  example.resolve(response({}, false));
  await pending;

  assert.equal(vm.runInContext("current.slug", workbench.context), "ledgerbridge");
  assert.deepEqual(workbench.errors, []);
});

test("a safe-example success is ignored after the review path changes", async () => {
  const example = deferred();
  const workbench = makeWorkbench([example]);
  const route = workbench.byId("input-route");
  const importField = workbench.byId("enterprise-json");
  route.value = "enterprise";
  route.dispatch("change");
  const pending = workbench.byText("Load safe example").click();

  route.value = "current";
  route.dispatch("change");
  route.value = "enterprise";
  route.dispatch("change");
  importField.value = "Keep the operator's current draft.";
  example.resolve(response({ bundle: { example: true } }));
  await pending;

  assert.equal(importField.value, "Keep the operator's current draft.");
  assert.deepEqual(workbench.errors, []);
});

test("a file-read failure from a previous workflow view is ignored", async () => {
  const fileRead = deferred();
  const workbench = makeWorkbench([]);
  const route = workbench.byId("input-route");
  const file = workbench.byId("enterprise-file");
  route.value = "enterprise";
  route.dispatch("change");
  file.files = [{ size: 32, text: () => fileRead.promise }];
  const pending = file.dispatch("change")[0];

  workbench.context.select("marketbrief");
  workbench.context.select("ledgerbridge");
  fileRead.reject(new Error("read failed"));
  await pending;

  assert.deepEqual(workbench.errors, []);
});

test("a file-read success cannot overwrite edits made while it is pending", async () => {
  const fileRead = deferred();
  const workbench = makeWorkbench([]);
  const route = workbench.byId("input-route");
  const file = workbench.byId("enterprise-file");
  const importField = workbench.byId("enterprise-json");
  route.value = "enterprise";
  route.dispatch("change");
  file.files = [{ size: 32, text: () => fileRead.promise }];
  const pending = file.dispatch("change")[0];

  importField.value = "Keep the operator's current draft.";
  importField.dispatch("input");
  fileRead.resolve("late file contents");
  await pending;

  assert.equal(importField.value, "Keep the operator's current draft.");
  assert.deepEqual(workbench.errors, []);
});

test("a failed HTTP response stays an error and is not rendered as a receipt", async () => {
  const failure = deferred();
  const { context, elements, errors, rendered } = makeWorkbench([failure]);
  const pending = context.submit({ preventDefault() {} });
  failure.resolve(response({ error: "The source is temporarily unavailable." }, false));
  await pending;

  assert.deepEqual(errors, ["The source is temporarily unavailable."]);
  assert.deepEqual(rendered, []);
  assert.equal(elements.get("run-button").disabled, false);
});

test("a file selection supersedes a safe example without disabling its control", async (t) => {
  for (const exampleSettlesFirst of [true, false]) {
    await t.test(exampleSettlesFirst ? "safe example settles first" : "file read settles first", async () => {
      const example = deferred();
      const fileRead = deferred();
      const workbench = makeWorkbench([example]);
      const route = workbench.byId("input-route");
      const importField = workbench.byId("enterprise-json");
      const exampleButton = workbench.byText("Load safe example");
      const file = workbench.byId("enterprise-file");
      route.value = "enterprise";
      route.dispatch("change");
      const examplePending = exampleButton.click();
      file.files = [{ size: 32, text: () => fileRead.promise }];
      const filePending = file.dispatch("change")[0];
      const controlAvailableOnSelection = !exampleButton.disabled;
      if (exampleSettlesFirst) {
        example.resolve(response({ bundle: { source: "older example" } }));
        await examplePending;
        fileRead.resolve("latest file contents");
        await filePending;
      } else {
        fileRead.resolve("latest file contents");
        await filePending;
        example.resolve(response({ bundle: { source: "older example" } }));
        await examplePending;
      }

      assert.equal(importField.value, "latest file contents", "the selected file remains the newest import");
      assert.equal(exampleButton.disabled, false, "settling either operation leaves the safe-example control available");
      assert.equal(controlAvailableOnSelection, true, "choosing a file takes over the import controls immediately");
      assert.deepEqual(workbench.errors, []);
    });
  }
});

test("a failed or oversized file read does not leave the safe-example control disabled", async (t) => {
  await t.test("failed file read", async () => {
    const example = deferred();
    const fileRead = deferred();
    const workbench = makeWorkbench([example]);
    const route = workbench.byId("input-route");
    const exampleButton = workbench.byText("Load safe example");
    const file = workbench.byId("enterprise-file");
    route.value = "enterprise";
    route.dispatch("change");
    const examplePending = exampleButton.click();
    file.files = [{ size: 32, text: () => fileRead.promise }];
    const filePending = file.dispatch("change")[0];
    fileRead.reject(new Error("read failed"));
    await filePending;
    example.resolve(response({ bundle: { source: "older example" } }));
    await examplePending;

    assert.equal(exampleButton.disabled, false);
    assert.deepEqual(workbench.errors, ["The local JSON file could not be read."]);
  });

  await t.test("oversized file", async () => {
    const example = deferred();
    const workbench = makeWorkbench([example]);
    const route = workbench.byId("input-route");
    const exampleButton = workbench.byText("Load safe example");
    const file = workbench.byId("enterprise-file");
    route.value = "enterprise";
    route.dispatch("change");
    const examplePending = exampleButton.click();
    file.files = [{ size: 120 * 1024 + 1, text: async () => "unused" }];
    await file.dispatch("change")[0];
    example.resolve(response({ bundle: { source: "older example" } }));
    await examplePending;

    assert.equal(exampleButton.disabled, false);
    assert.deepEqual(workbench.errors, ["The JSON file exceeds the 120 KB processing limit."]);
  });

  await t.test("cancelled file selection", async () => {
    const example = deferred();
    const workbench = makeWorkbench([example]);
    const route = workbench.byId("input-route");
    const exampleButton = workbench.byText("Load safe example");
    const file = workbench.byId("enterprise-file");
    route.value = "enterprise";
    route.dispatch("change");
    const examplePending = exampleButton.click();
    file.files = [];
    await file.dispatch("change")[0];
    example.resolve(response({ bundle: { source: "older example" } }));
    await examplePending;

    assert.equal(exampleButton.disabled, false);
    assert.deepEqual(workbench.errors, []);
  });
});
