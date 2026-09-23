> **Operator model:** the reader is a non-technical goal-bringer. Plain English first; technical details only where they verify the work.

# PipelineRelay

PipelineRelay's normal command reads only permitted metadata for the public `pytest-dev/pytest` GitHub repository and prepares a human verification task. The exact [repository metadata API](https://api.github.com/repos/pytest-dev/pytest) response identifies the repository and its MIT license; the corresponding [GitHub MIT license metadata](https://api.github.com/licenses/mit) is recorded as the terms reference. The app does not read README or issue text and does not create sales leads, contacts, CRM claims, or consent claims.

From the repository root:

```sh
python3 -m apps.pipelinerelay
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s apps/pipelinerelay/tests -v
```

The returned metadata includes the exact GitHub repository URL and stable ID, `updated_at` as-of time, retrieval UTC, returned MIT license reference, response hash, task-fit declaration, and zero side effects. The license reference is for the public repository's metadata; it does not establish reuse rights for other GitHub content. An optional local model sees only those live admitted metadata fields and must cite that repository; app-reported output is not independently verified.

**Important limit:** public GitHub metadata is not private PipelineRelay account/CRM data, a lead, user consent, or permission to contact anyone. R07 remains `UNVERIFIED` until an authorized CRM/account source, consent evidence, and an accountable owner exist. No outreach adapter exists.

`run_demo()` and its synthetic consent/account fixtures remain for fixture regression tests only. The normal CLI uses the live repository metadata route and never falls back to those fixtures. The shared ten-workflow runner still needs a separately scoped integration update before it can select these live paths by default.
