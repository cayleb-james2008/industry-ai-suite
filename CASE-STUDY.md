# Industry AI Suite — project case study

I’ve been working on Industry AI Suite as an independent engineering project. It brings together ten workflow prototypes on a shared Python core. I kept coming back to one question: can a tool make a useful first pass without acting like missing evidence is there?

## The approach

The suite covers bounded review tasks in finance, research, security triage, content, sales handoffs, customer support, workplace knowledge, and onboarding. I wanted to avoid ten disconnected demos. The workflows share code for source checks, privacy-aware handling, evidence-linked results, and human review.

There are two different paths in the local workbench. The source-backed routes make narrow, read-only requests to named sources; ChainWatch stays disconnected until a suitable source is verified. Those public records do not stand in for private company data. The organization-import path accepts a user-supplied, de-identified bundle and runs a product-specific check in memory. Its safe examples are invented engineering data. They are deterministic: they do not call a model, save the submitted input on the server, or trigger an external action.

A result keeps the source state separate from the full-workflow status. It can show the evidence and a next step for a reviewer while still saying `UNVERIFIED`. If a source is unavailable or its use cannot be established, the suite does not fill the gap with a fixture or stale result.

## What a reviewer can inspect

A fresh checkout can run the local workbench without an API key or a model server. From there, a reviewer can inspect ten distinct organization-import examples, see each bounded result and handoff, and read the source and privacy limits in the receipt. The [README](README.md) has the setup steps; [FREE-PATHS.md](FREE-PATHS.md) maps the public and local paths; [ENTERPRISE-INPUTS.md](ENTERPRISE-INPUTS.md) describes the import boundary.

The 26 September 2026 witness bundle records six local model exchanges; five produced app-accepted, source-cited output. The first OnboardPath call failed the citation check; its corrected sixth call passed. These are specific, dated examples—not a claim that every workflow uses a model or that a provider was contacted during this verification.

## What I have not established

The local examples are not company data. The importer cannot authenticate a person, prove an organization's authority, or establish that submitted records are complete. All ten full enterprise workflows remain `UNVERIFIED`; production deployment, customer use, revenue, and commercial outcomes are not established. The public-source routes cover narrow slices, not completed business workflows. The workbench cannot trade, sign, send messages, or change an account.

That boundary is part of the project, not a footnote: when the evidence or permission is missing, the result should stop at a review handoff rather than imply the work is done.
