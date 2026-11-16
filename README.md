# Web Witness Agent — zkVerify Agent Games (Wildcard)

An AI-agent-friendly service that turns **"what an agent saw on the web"** into an
independently checkable fact. Give it a URL and the field you care about; it fetches
the real response, extracts the claim, signs it (Ed25519), commits to it (SHA-256),
and anchors that commitment on **zkVerify** — without storing or exposing the full
payload.

**One-line pitch:** agents act on web data all the time (prices, terms, availability,
status codes) — Web Witness gives them a way to *prove* what they acted on, to anyone,
later.

## The problem it solves

Today, when an autonomous agent makes a decision based on a web/API observation
("I paid because the API said the FX rate was X", "I booked because slot Y was free"),
that observation is unverifiable after the fact. Counterparties, auditors, and even
the agent's own operator have to take the agent's word for it — or archive entire
payloads, which is wasteful and can leak data the agent shouldn't share.

Web Witness solves this with a three-layer proof, each layer independently checkable:

1. **Signature** — every claim is signed with the agent's Ed25519 key (published at
   `GET /publickey`). Tampering with any field of a claim breaks verification.
2. **Commitment** — `SHA-256(canonical JSON of the claim core)`. Anyone can recompute
   it from the public claim document. It binds the *exact* claim content.
3. **On-chain anchor** — the commitment is written to zkVerify as a
   `system.remark` extrinsic with payload `webwitness/v1/<commitment>`. Once the
   extrinsic is finalized, the claim is timestamped by the chain and cannot be
   retroactively altered or denied.

The full payload is **not** published — only the extracted claim. This is the
"prove what your agent saw, without revealing the full payload" pattern.

## Who it helps

- **Agent developers** — drop one HTTPS call before acting on third-party data and
  your agent gets a non-repudiable observation log.
- **Agent-to-agent commerce** — a paying agent can show the seller (or an arbiter)
  exactly which price/terms it relied on, with a chain-timestamped commitment.
- **Compliance/audit** — an operator can prove what its agent observed without
  dumping raw payloads (which may contain unrelated private data).

## Live endpoints (production deployment)

| Route | Purpose |
|---|---|
| `GET /` | Demo UI — witness a URL in the browser |
| `POST /witness` | Observe + extract + sign + enqueue anchor |
| `GET /claims/:id` | Claim document (live anchor status) |
| `GET /claims/:id/verify?refetch=1` | Full verification report (+ optional live re-check) |
| `GET /publickey` | Agent's Ed25519 public key |
| `GET /healthz` | Liveness + config fingerprint |

### Try it

```bash
curl -sS -X POST https://<host>/witness \
  -H 'content-type: application/json' \
  -d '{"url":"https://api.coinbase.com/v2/prices/BTC-USD/spot","mode":"jsonpath","path":"data.amount"}'
```

Response (truncated):

```json
{
  "v": 1,
  "id": "wit_9f2c…",
  "request": { "url": "https://api.coinbase.com/v2/prices/BTC-USD/spot", "mode": "jsonpath", "path": "data.amount" },
  "response": { "status": 200, "sha256": "…", "size": 89, "fetched_at": "2026-11-17T…" },
  "claim":   { "mode": "jsonpath", "spec": "data.amount", "value": 97412.34 },
  "commitment": "e3b0c442…",
  "signature": "…ed25519…",
  "anchor": { "status": "pending", "network": "volta" }
}
```

Then verify:

```bash
curl -sS "https://<host>/claims/<id>/verify?refetch=1"
```

The report re-checks the signature and the commitment recomputation, shows the
anchor status + explorer URL, and — with `refetch=1` — re-fetches the URL right now
and compares hash and value, with an honest note: a mismatch means *the source
changed*, not that the original claim was fabricated.

## How the checkable claim works

```
POST /witness {url, extract-spec}
        │
        ▼
 SSRF-guarded fetch (public hosts only, per-hop DNS check, size/time caps)
        │
        ▼
 extract claim (JSON path or regex; missing ⇒ error, NEVER fabricated)
        │
        ▼
 core = {v, id, created_at, request, response{status,sha256,size,…}, claim}
 commitment = SHA-256(canonicalJson(core))
 signature  = Ed25519(canonicalJson(core))
        │
        ▼
 store claim → respond immediately (anchor: pending)
        │            └──► background worker
        │                    system.remark("webwitness/v1/<commitment>")
        │                    → zkVerify (Volta testnet / mainnet)
        ▼
 GET /claims/:id/verify → signature ✓ · commitment ✓ · anchor + explorer link ✓
```

Anyone can audit a claim in three independent steps:

1. **Offline crypto check** — recompute `canonicalJson(core)`; verify the Ed25519
   signature against `GET /publickey` and the SHA-256 against `commitment`.
2. **Chain check** — open the explorer URL from `anchor.explorer_url`; the
   `system.remark` argument must equal `webwitness/v1/<commitment>`.
3. **Source check (optional)** — `verify?refetch=1` re-observes the URL now and
   reports whether the body hash / extracted value still match.

## What is trusted and what is not (honest trust model)

| Aspect | Status |
|---|---|
| Claim content was not tampered with after creation | ✅ cryptographic (signature + commitment) |
| Claim existed at time T (timestamp) | ✅ on-chain (finalized remark) |
| Agent actually contacted the URL it says it did | ✅ recorded `final_url` + response hash; but see limitation L1 |
| Extracted value really occurs inside the full payload | ⚠️ trusted to the agent **today** (see roadmap) |
| Payload bytes themselves | not published; only their SHA-256 is committed |

**Known limitations (stated plainly):**

- **L1 — TLS trust.** The fetch runs server-side over TLS; the agent sees plaintext
  like any client. Web Witness proves *what the agent extracted from what it
  received*; it does not (yet) prove the TLS session contents to a third party the
  way full zkTLS (e.g. Reclaim/TLSNotary) does.
- **L2 — extraction binding.** The commitment covers the claim, not the payload
  body. A malicious deployment could extract dishonestly. The roadmap removes this
  trust with a Groth16 containment proof.
- **L3 — regex DoS.** User-supplied regexes are length-capped (256 chars) and bodies
  are size-capped (1 MB default), but Node's regex engine has no execution timeout.

## Roadmap: closing L2 with a real SNARK

The natural next step (and the reason this agent pairs naturally with zkVerify's
proof-verification machinery):

- Compile a small circom circuit: private inputs = payload chunks + offset;
  public inputs = `SHA-256(payload)` and the claimed bytes; constraint proves
  the claimed bytes appear in the committed payload.
- Submit the Groth16 proof via Kurier with the claim id as the linkage — turning
  "trust the extraction" into "verify the proof".
- The harness, canonical-JSON layer, and Kurier integration pattern already exist
  in the operator's Proof Gatekeeper agent (same toolchain: snarkjs, Groth16,
  BN254), so this is an incremental upgrade, not a rewrite.

## Build decisions worth knowing

- **Fail-fast, never fabricate.** A failed fetch, a blocked target, or a missing
  extraction path returns an error — no claim document is created. An agent that
  "sometimes invents" is worse than useless in an audit setting.
- **SSRF hardening is a first-class feature.** A URL-fetching service is an SSRF
  cannon aimed at its own VPC. Every redirect hop is re-resolved and re-checked;
  loopback/private/reserved/link-local (incl. cloud metadata `169.254.169.254`)
  addresses are refused; embedded credentials are refused; bodies are streamed
  with a hard cap. The tests cover each of these (`test/harness.ts`).
- **Canonical JSON.** Commitments hash a recursive key-sorted, whitespace-free
  serialization, so verification doesn't depend on object key order.
- **Anchoring is asynchronous.** Witness responses return in milliseconds; the
  chain anchor completes in the background and the verify endpoint reflects live
  status. Claims are still fully signed and checkable before the anchor lands.
- **No payload storage.** The store keeps claim documents only (compact, no raw
  bodies) — this is what makes "without revealing the full payload" real.
- **Env-only secrets.** The anchor account seed never appears in code, logs
  (redacting logger), or the repo.

## Repository layout

```
├── public/index.html          # self-contained demo UI (no CDN, no build step)
├── src/
│   ├── main.ts                # entry point
│   ├── server.ts              # HTTP surface: routes, rate limiting, verify reports
│   ├── config.ts              # env-only configuration
│   ├── witness.ts             # pipeline: fetch → extract → sign → store → enqueue
│   ├── fetcher.ts             # SSRF-hardened fetcher (DNS-per-hop, caps)
│   ├── extract.ts             # JSON-path / regex extraction (scalar-only claims)
│   ├── claim.ts               # canonical JSON, commitment, Ed25519 binding
│   ├── keys.ts                # signing key lifecycle (0600 on disk)
│   ├── anchor.ts              # zkVerify anchor worker (system.remark, async)
│   ├── store.ts               # atomic JSON-file claim store
│   └── log.ts                 # redacting structured logger
├── test/
│   ├── fixtures.ts            # local fixture HTTP server
│   └── harness.ts             # 50 checks: crypto, SSRF negatives, HTTP e2e
├── deploy/
│   ├── web-witness.service    # systemd unit
│   └── WITNESS-DEPLOY.md      # VPS runbook (Caddy + systemd + faucet)
└── .env.example               # every knob documented
```

## Setup

```bash
npm install
npm run build
npm test        # 50 local checks — no network, no secrets needed
cp .env.example .env   # then configure ANCHOR_MODE + ZKV_ANCHOR_SEED (see .env.example)
npm start
```

Local dev with anchoring disabled works out of the box (`ANCHOR_MODE=none`):
claims are signed and verifiable, the demo UI and all endpoints are functional.

To enable the on-chain anchor: create an account (polkadot.js or any Substrate
wallet), fund it with a little Volta testnet VFY from the faucet (a `remark` costs
fractions of a cent), then:

```env
ANCHOR_MODE=volta
ZKV_ANCHOR_SEED=<twelve words>
```

## Submission context (Agent Games — Wildcard)

- **Agent link:** this repository (code + tests + runbook + demo UI).
- **Public endpoint:** `https://<witness-host>/` (demo UI, live API).
- **Use case:** provable web observations for autonomous agents — see above.
- **Build context:** this README (decisions, trust model, limitations).
- **zkVerify angle (the optional plus):** the on-chain `system.remark` anchor —
  a finalized, explorer-visible commitment that binds every claim to a chain
  timestamp. `GET /claims/:id/verify` shows the exact explorer link per claim.
