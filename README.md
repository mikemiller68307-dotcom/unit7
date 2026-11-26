# Unit 7 – AI Provenance & Evidence Auditor

**Origin & Architecture Lead:** Mike Enenkel · **Mensch maschine projekt (MMP)**, Wissembourg, France (2026)

Unit 7 is a deterministic provenance and evidence auditor for AI-generated empirical statements. It does **not** claim to measure psychological "intent" or "honesty" of a model. Instead, it separates atomic claims into:

1. **Execution Provenance** (Was an approved measurement tool actually executed on the inspected asset before the answer was generated?)
2. **Numerical / Dimension Consistency** (Does the claimed value match the cryptographically signed tool output within explicit rounding tolerances?)
3. **Scope / Channel Validity** (Does the claim stay within the measured channel, region of interest, and parameter scope?)

All verification runs **100% client-side** in the visitor's browser via standard WebCrypto (`Ed25519` + `SHA-256`) and a deterministic rule kernel (`0 LLM calls`, zero background telemetry).

## Unit 7 V2 – "The Human Layer" (Cognitive Integrity Protocol)

V2 extends the deterministic kernel with the **Cognitive Integrity Protocol (CIP)** and reorganizes the audit as a three-level **responsibility chain** (Human Input → Tool/KI Execution → Human Claim). Core principle: *the AI is witness and tool – never the culprit.* Missing evidence yields `UNVERIFIED`, never "lied".

V2 ships as a fully self-contained single-file app (zero build step, zero dependencies, own RFC 8032 Ed25519 verifier):

- **Repo file:** [`public/unit7-v2.html`](public/unit7-v2.html) (copied into the build via Vite `publicDir`)
- **Live page (GitHub Pages build output):** [`docs/unit7-v2.html`](docs/unit7-v2.html)
- Open locally: download the file and open it in any modern browser – 100% client-side, no account, no telemetry.

What V2 adds on top of V1:

| Layer | Check |
| --- | --- |
| A – Execution | Signed run manifest covers the claimed tool/analysis |
| B – Value & Unit | Claimed numbers/units/hashes match signed tool output exactly |
| C – Scope | Claim reach stays within the logged data access (thumbnail vs. original) |
| D – Key Trust | `valid_ed25519` strictly separated from `trusted_key`; foreign but valid keys → `UNTRUSTED_KEY` |
| E – Mirroring | Sycophancy/premise mirroring, phantom citations, prompt-injection traces |
| CIP | Statement decomposition, arithmetic consistency, certainty-vs-evidence coupling, counterfactual lab (variants A–E), auditor self-disclosure |

V2 includes 11 interactive sandbox reference cases (8 adversarial + 3 Cognitive-Integrity/Human-Layer cases) with real build-time Ed25519 signatures, a local trusted-key registry, dark/light mode, and deterministic audit-JSON export.

## Build & Verify Locally

```bash
npm install
npm test
npm run build
```

© 2026 Mike Enenkel / Mensch maschine projekt (MMP). All rights reserved.
