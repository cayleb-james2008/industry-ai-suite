> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# PipelineRelay

**Business need:** A salesperson summarizes permitted account context and hands an appropriate next step to an owner. **Current live slice:** PipelineRelay checks metadata for a selected public GitHub repository and prepares a public-research review; it is not a sales-account workflow.

The default repository is `pytest-dev/pytest`. To select another repository, pass both safe path segments:

```sh
python3 -m apps.pipelinerelay --owner pallets --repo flask
```

Both values must be supplied together. Inputs are single owner/repository path segments, not URLs or paths; malformed, partial, traversal, slash, or query input is rejected before a request. The command uses the shared `suite_core.fetch_live(Provider.GITHUB_REPOSITORY, ...)` adapter and reads repository metadata only. It reports the returned repository ID, full name, default branch, source `updated_at` plus its observed age, and the exact returned SPDX identifier/terms URL. Missing or ambiguous license metadata, or a mismatch between the SPDX identifier and terms URL, fails closed. The app does not read repository README, issue, advisory, or contact text.

From the repository root:

```sh
python3 -m apps.pipelinerelay
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/pipelinerelay/tests -v
```

The structured handoff includes the exact GitHub repository URL and stable ID, source `updated_at` and signed age at retrieval, the returned SPDX identifier and its exact terms URL, response hash, task-fit declaration, and zero side effects. The update time is a source observation, not proof of current repository activity or code contents. The returned terms URL is a repository-metadata reference; it does not grant reuse rights for README, issue, advisory, or other content. This slice intentionally has no honest AI role: a model-generated sales summary from public repository metadata would add unsupported account meaning.

**Important limit:** public GitHub metadata is not private PipelineRelay account/CRM data, a lead, user consent, or permission to contact anyone. R07 remains `UNVERIFIED` until an authorized CRM/account source, consent evidence, and an accountable owner exist. No outreach adapter exists.

`run_demo()` and its synthetic consent/account fixtures remain for fixture regression tests only. The normal CLI uses the live repository metadata route and never falls back to those fixtures. The full sales workflow remains `UNVERIFIED` until authorized CRM/account data, consent evidence, and an accountable owner exist; public repository facts do not create a lead or imply permission to contact anyone. No outreach occurs. The shared ten-workflow runner still needs a separately scoped integration update before it can pass a user-selected repository through its own interface.
