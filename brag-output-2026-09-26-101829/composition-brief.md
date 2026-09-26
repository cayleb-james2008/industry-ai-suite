# Hyperframes Composition Brief: Industry AI Suite

## Objective
Create a short launch-style brag video for the Industry AI Suite (yc-parody).

## Output
- Composition directory: `/home/cayleb/Work/projects/industry-ai-suite/brag-output-2026-09-26-101829/composition/`
- Rendered video: `/home/cayleb/Work/projects/industry-ai-suite/brag-output-2026-09-26-101829/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 21 seconds

## Source Material
- Project root: /home/cayleb/Work/projects/industry-ai-suite
- Primary files read: README.md, receipts structure (source URL / retrieved UTC / sha256 / task_result / uncertainty)
- Product name: Industry AI Suite
- Tagline / strongest claim: "Every claim ships with a receipt." — "honesty as an architecture"
- Key UI or visual moment to recreate: a real receipt card (World Bank fields) and the run_all terminal output
- Copy that must appear verbatim:
  - "We built ten AI products." / "None of them lie."
  - "Suite status: INCOMPLETE" / "UNVERIFIED=10" / "exit code 1" / "on purpose."
  - "Every claim ships with a receipt."
  - The ten app names: LedgerBridge, MarketBrief, ChainWatch, BacktestGuard, ReplyCraft, HandoffHub, SentinelDesk, SearchLift, PipelineRelay, OnboardPath
  - Receipt fields: "source: api.worldbank.org/…" / "retrieved: 2026-09-26T12:24:08Z" / "sha256: e48bfc08…f7d0" / stamp "UNVERIFIED"

## Creative Direction
- Tone preset: yc-parody
- Creative direction: fake-serious startup launch for an anti-vaporware product; the honesty is real, that's the joke
- Interpretation: structured deadpan; UNVERIFIED badges treated like award seals
- Angle: in a market of AI vaporware, this suite ships receipts and honest labels
- Hook: "We built ten AI products." → "None of them lie."
- Outro / punchline: "exit code 1 — on purpose." mid-video; outro "Every claim ships with a receipt."
- Avoid:
  - Any claim the suite doesn't make (no customers, no revenue, no "AI-powered" hype)
  - Generic SaaS language
  - Loud or dense SFX (deadpan)

## Visual Identity
- Background: #F3F6F8 (light editorial)
- Surface: #FFFFFF
- Text: #172B3A ink / #4B5D69 muted
- Accent: #B6422A (signal rust — UNVERIFIED stamp, accent rules); #123F70 for terminal/mono accents
- Display font: system-ui bold; monospace for receipt/terminal
- Visual references: suite README table; receipt JSON field names

## Storyboard
Use the storyboard in `/home/cayleb/Work/projects/industry-ai-suite/brag-output-2026-09-26-101829/brag-plan.md` as the creative contract.

Scene summary:
1. Deadpan intro — 3.5s — "We built ten AI products." / "None of them lie."
2. The ten — 5s — ten app names land one by one with status chips, full grid holds
3. The receipt — 4.5s — receipt card fields appear, UNVERIFIED stamp slams ("the badge it earned by telling the truth")
4. Exit code 1 — 4.5s — terminal types run_all, INCOMPLETE output, "on purpose." punchline
5. Outro — 3.5s — "Every claim ships with a receipt." + tagline

## Audio
- Audio role: sparse professional accents over a warm business bed
- Audio arc: steady low bed; dips under the stamp; fades under outro
- Music: happy-beats-business-moves-vol-9-by-ende-dot-app.mp3
- Music treatment: 0.26 volume, fade from 19s
- Music cue guidance: preset JSON at /home/cayleb/.agents/skills/brag/assets/music/cues/happy-beats-business-moves-vol-9-by-ende-dot-app.music-cues.json — read for strong cues; lock the receipt stamp and the "on purpose." punchline to nearest strong cues
- Audio-reactive treatment: none (deadpan restraint)
- Audio-coupled moments:
  - Scene 2 name grid — soft drop per name (accent every other), stack sound on completion
  - Scene 3 stamp — one chunky stamp impact (impactPlate or similar, low HF risk)
  - Scene 4 — quiet key ticks, soft line drops, one dry hit on the punchline
- SFX selection guidance: sparse; never more than one SFX at a time
- SFX analysis guidance: /home/cayleb/.agents/skills/brag/assets/sfx/sfx-analysis.md
- Exact SFX choice: Hyperframes decides exact files/timestamps/density/volume
- Audio files: copy chosen music + SFX into composition/assets/

## Hyperframes Instructions
Load `hyperframes-core`, `hyperframes-animation`, `hyperframes-creative`, `hyperframes-keyframes`, `hyperframes-cli`. /brag owns angle, copy, tone, storyboard; Hyperframes owns composition structure, exact timing, mechanics, lint, render.

Requirements:
- Light editorial theme (not dark) — this suite's identity is paper-and-receipt
- Ten-name grid: sequential reveal at readable spacing (every other beat), full set holds ≥2s
- Receipt card with the exact fields listed; stamp framed as a seal of honor
- Keep all text readable; honor reading floors
- 21 seconds total, 1920x1080
- At least one beat-locked major reveal marked `// beat-locked`
- Run `npx hyperframes check` before render — zero errors required
