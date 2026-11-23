# Unit 7 – AI Provenance & Evidence Auditor

**Origin & Architecture Lead:** Mike Enenkel · **Mensch maschine projekt (MMP)**, Wissembourg, France (2026)

Unit 7 is a deterministic provenance and evidence auditor for AI-generated empirical statements. It does **not** claim to measure psychological "intent" or "honesty" of a model. Instead, it separates atomic claims into:

1. **Execution Provenance** (Was an approved measurement tool actually executed on the inspected asset before the answer was generated?)
2. **Numerical / Dimension Consistency** (Does the claimed value match the cryptographically signed tool output within explicit rounding tolerances?)
3. **Scope / Channel Validity** (Does the claim stay within the measured channel, region of interest, and parameter scope?)

All verification runs **100% client-side** in the visitor's browser via standard WebCrypto (`Ed25519` + `SHA-256`) and a deterministic rule kernel (`0 LLM calls`, zero background telemetry).

## Build & Verify Locally

```bash
npm install
npm test
npm run build
```

© 2026 Mike Enenkel / Mensch maschine projekt (MMP). All rights reserved.
