# Brag Plan: Industry AI Suite

## What is this app?
Ten workflow apps on one shared foundation where every claim ships with a receipt — public-data slices verified with source URLs, hashes, and honest UNVERIFIED labels baked into the product.

## The angle
Y Combinator parody delivered dead-straight: "We built ten AI products. None of them lie." In a market of AI vaporware, the suite's radical feature is that it tells you exactly what it hasn't proven — in writing, with hashes. The exit-code-1-on-purpose is the mic drop.

## Hook (first 2-3 seconds)
Deadpan startup intro card: "We built ten AI products." Beat. "None of them lie."

## Key moments (the middle)
- The ten app names land as a clean grid, one by one on the beat grid, each with a status chip.
- A real receipt card gets recreated field by field: source URL, retrieval UTC, SHA-256 hash, and the big red "UNVERIFIED" badge treated as a feature stamp, not a failure.
- Terminal: `python3 scripts/run_all.py` types out → "Suite status: INCOMPLETE" → "UNVERIFIED=10" → "exit code 1. on purpose."

## Outro / punchline
"Every claim ships with a receipt." + "Industry AI Suite — honesty as an architecture."

## User flow worth showing
Run the suite → receipts print → exit code 1 with the honest summary. That IS the product flow (there is no flashier flow yet — and the video says so proudly).

## Tone
- Preset: yc-parody
- Creative direction: fake-serious startup launch for an anti-vaporware product; the joke is that the honesty is real
- Interpretation: structured, deadpan delivery, restrained SFX; the humor comes from treating UNVERIFIED badges like award seals

## Format: landscape — 1920x1080
## Duration: 21 seconds

## Visual identity (from the project)
- Background: #F3F6F8 (light editorial)
- Surface: #FFFFFF
- Text: #172B3A ink / #4B5D69 muted
- Accent: #B6422A (signal rust — used for the UNVERIFIED stamps and CTA)
- Deep blue: #123F70 (focus, for links/terminal accents)
- Display font: system-ui bold; monospace for receipts/terminal
- Strongest visual element: the receipt card with real field names from the suite's receipts

## Share copy (draft)
We built ten AI products. None of them lie. Every claim in the Industry AI Suite ships with a receipt — source URL, timestamp, SHA-256 — and an honest UNVERIFIED badge when it hasn't earned a checkmark. Exit code 1 while incomplete. On purpose.

## Audio direction
- Role: sparse professional accents over a warm business bed
- Music: happy-beats-business-moves-vol-9-by-ende-dot-app.mp3 (mid-energy, laid-back)
- Music treatment: 0.26 volume, steady, fade under outro
- Music cue guidance: preset JSON at assets/music/cues/ (read at composition); lock the receipt-stamp moment and the exit-code punchline to strong cues from the preset
- Audio-reactive treatment: none (deadpan restraint)
- SFX posture: sparse; 3-4 cues
- Audio-coupled moments: app-name grid (soft drops on beat grid), receipt stamp (one chunky stamp impact), terminal typing (quiet keys), punchline (one dry hit)
- Restraint rule: the joke is deadpan — never more than one SFX at a time

## Storyboard

### Scene 1 — Deadpan intro — 3.5s
Clean light card, startup-serif energy: "We built ten AI products." holds. Hard cut: "None of them lie." holds longer than expected (that's the joke).
Sequential/interaction: two text beats, long holds
Audio intent: dry, confident
Audio-coupled idea: none on line 1; soft drop on line 2
Music: vol-9 low
Transition mood: hard cut → Scene 2

### Scene 2 — The ten — 5s
White grid; ten app names land one by one (LedgerBridge, MarketBrief, ChainWatch, BacktestGuard, ReplyCraft, HandoffHub, SentinelDesk, SearchLift, PipelineRelay, OnboardPath), each with a tiny status chip. Grid holds complete after landing all ten.
Sequential/interaction: yes — 10 items on the beat grid at readable spacing (every other beat), full set holds ≥2s
Audio intent: roll-call confidence
Audio-coupled idea: soft drop per name (accent every other), stack sound on completion
Music: bed
Transition mood: slide → Scene 3

### Scene 3 — The receipt — 4.5s
One receipt card scales in. Fields type/appear: `source: api.worldbank.org/...` / `retrieved: 2026-09-26T12:24:08Z` / `sha256: e48bfc08…f7d0` / then the big rust stamp slams: "UNVERIFIED" — framed as a seal of honor with the caption "the badge it earned by telling the truth."
Sequential/interaction: yes — field lines, then stamp
Audio intent: bureaucratic comedy
Audio-coupled idea: quiet keys per field, one chunky stamp impact on the badge
Music: bed dips under stamp
Transition mood: clean → Scene 4

### Scene 4 — Exit code 1 — 4.5s
Terminal (light theme): `python3 scripts/run_all.py` types out. Output: "Suite status: INCOMPLETE" / "Workflow job statuses: UNVERIFIED=10" / "exit code 1" — then the deadpan punchline in huge ink type: "on purpose."
Sequential/interaction: yes — typed command, output lines, punchline
Audio intent: the mic drop
Audio-coupled idea: key ticks, soft line drops, one dry hit on "on purpose."
Music: bed fades
Transition mood: hard cut → Scene 5

### Scene 5 — Outro — 3.5s
"Every claim ships with a receipt." Center, ink on light. Under: "Industry AI Suite · honesty as an architecture" with the rust accent rule.
Sequential/interaction: two beats
Audio intent: quiet close
Audio-coupled idea: soft drop on the tagline
Music: out
Transition mood: soft fade

**Music mood for this video:** deadpan business
**Audio summary:** laid-back low bed, bureaucratic comedy accents, one stamp impact, dry punchline hit, quiet close.
