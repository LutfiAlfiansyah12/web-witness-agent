/**
 * Public HTTP surface.
 *
 *   GET  /                    → demo page (public/index.html)
 *   GET  /healthz             → liveness + config fingerprint
 *   GET  /publickey           → Ed25519 public key for offline verification
 *   POST /witness             → observe a URL, extract a claim, sign + anchor
 *   GET  /claims/:id          → claim document (live anchor status)
 *   GET  /claims/:id/verify   → full verification report (?refetch=1 re-checks)
 *
 * CORS is open (public API); per-IP token-bucket rate limiting protects the
 * outbound fetch budget.
 */
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { log } from './log.js';
import { getKeys } from './keys.js';
import { canonicalJson, verifyClaimDoc, sha256Hex, type ClaimDoc } from './claim.js';
import { ClaimStore } from './store.js';
import { AnchorWorker } from './anchor.js';
import { witness, parseWitnessRequest, WitnessRequestError } from './witness.js';
import { fetchWitness, defaultFetchOptions, FetchError } from './fetcher.js';
import { extractJsonPath, extractRegex, ExtractError } from './extract.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../public');

// ── Rate limiter (per-IP fixed window) ──────────────────────────────────────

const buckets = new Map<string, { count: number; resetAt: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || b.resetAt <= now) {
    buckets.set(ip, { count: 1, resetAt: now + config.rateLimit.windowMs });
    return false;
  }
  b.count += 1;
  return b.count > config.rateLimit.max;
}

// Periodic cleanup so the map never grows unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.resetAt <= now) buckets.delete(k);
}, 60_000).unref();

// ── Helpers ──────────────────────────────────────────────────────────────────

const MAX_REQUEST_BODY = 16 * 1024;

function json(res: http.ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
  res.end(data);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > MAX_REQUEST_BODY) {
        reject(new WitnessRequestError('TOO_LARGE', 'request body exceeds 16KB'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function ipOf(req: http.IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown';
}

const STATUS_FOR_CODE: Record<string, number> = {
  BAD_REQUEST: 400,
  INVALID_URL: 400,
  TOO_LARGE: 413,
  BLOCKED_TARGET: 403,
  DNS_FAILURE: 502,
  FETCH_FAILED: 502,
  TOO_MANY_REDIRECTS: 502,
  TIMEOUT: 504,
};

// ── Verification report ──────────────────────────────────────────────────────

async function buildVerifyReport(doc: ClaimDoc, refetch: boolean): Promise<unknown> {
  const { signature_valid, commitment_matches } = verifyClaimDoc(doc, getKeys().publicKeyHex);
  const report: Record<string, unknown> = {
    claim_id: doc.id,
    checked_at: new Date().toISOString(),
    signature: {
      algorithm: 'Ed25519',
      valid: signature_valid,
      public_key_hex: getKeys().publicKeyHex,
    },
    commitment: {
      algorithm: 'SHA-256 over canonical JSON of the claim core',
      value: doc.commitment,
      matches: commitment_matches,
    },
    anchor: {
      status: doc.anchor.status,
      network: doc.anchor.network,
      remark: doc.anchor.remark,
      tx_hash: doc.anchor.tx_hash,
      block_hash: doc.anchor.block_hash,
      explorer_url: doc.anchor.explorer_url,
      error: doc.anchor.error,
      how_to_check: doc.anchor.tx_hash
        ? 'Open the explorer URL, locate the system.remark extrinsic, and compare its remark argument with the commitment above — they must be equal (prefix webwitness/v1/).'
        : doc.anchor.status === 'pending' || doc.anchor.status === 'submitted'
          ? 'Anchor submission in progress — re-check in a minute.'
          : doc.anchor.status === 'disabled'
            ? 'Anchoring is disabled on this deployment (ANCHOR_MODE=none). The claim is still signed and hash-committed.'
            : doc.anchor.error ?? 'Anchor not available.',
    },
  };

  if (refetch) {
    try {
      const opts = defaultFetchOptions();
      const again = await fetchWitness(doc.request.url, opts);
      const text = again.bytes.toString('utf8');
      let currentValue: string | number | boolean | null;
      try {
        currentValue =
          doc.request.mode === 'jsonpath'
            ? extractJsonPath(text, doc.request.path!).value
            : extractRegex(text, doc.request.regex!, doc.request.group ?? 0).value;
      } catch (e) {
        currentValue = `<extraction failed now: ${(e as Error).message}>`;
      }
      const sameHash = sha256Hex(again.bytes) === doc.response.sha256;
      const sameValue = JSON.stringify(currentValue) === JSON.stringify(doc.claim.value);
      report.refetch = {
        fetched_at: new Date().toISOString(),
        status: again.status,
        sha256: sha256Hex(again.bytes),
        sha256_matches_original: sameHash,
        value_now: currentValue,
        value_matches: sameValue,
        note:
          'Web data changes — a mismatch here means the source changed since the observation, ' +
          'not that the original claim was fabricated. A match reconfirms both. The binding ' +
          'evidence for the original claim is the signature + the on-chain commitment.',
      };
    } catch (e) {
      report.refetch = { error: String((e as Error).message).slice(0, 200) };
    }
  }
  return report;
}

// ── App wiring ───────────────────────────────────────────────────────────────

export interface App {
  server: http.Server;
  store: ClaimStore;
  anchor: AnchorWorker;
  /** Resolves with the actually-bound port (supports port 0 in tests). */
  listen: () => Promise<number>;
}

export function initApp(): App {
  const store = new ClaimStore(config.dataDir);
  const anchor = new AnchorWorker();
  anchor.start(store);

  const deps = { store, anchor };

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url ?? '/', 'http://local');
    const finish = (status: number) =>
      log.info('req', { method: req.method, path: url.pathname, status, ms: Date.now() - started });

    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-headers': 'content-type',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
        });
        res.end();
        return;
      }

      // Static demo page.
      if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
        const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'));
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end(html);
        finish(200);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/healthz') {
        json(res, 200, {
          ok: true,
          uptime_s: Math.round(process.uptime()),
          anchor_mode: config.anchor.mode,
          claims_stored: store.size,
          allow_private_targets: config.fetch.allowPrivateTargets,
        });
        finish(200);
        return;
      }

      if (req.method === 'GET' && url.pathname === '/publickey') {
        json(res, 200, {
          algorithm: 'Ed25519',
          public_key_hex: getKeys().publicKeyHex,
          usage:
            'Verify any claim signature: canonicalJson(core) must (a) hash to commitment (SHA-256) and (b) verify under this key. Core = claim doc minus signature and anchor.',
        });
        finish(200);
        return;
      }

      if (req.method === 'POST' && url.pathname === '/witness') {
        const ip = ipOf(req);
        if (rateLimited(ip)) {
          json(res, 429, { error: { code: 'RATE_LIMITED', message: 'too many requests — slow down' } });
          finish(429);
          return;
        }
        const raw = await readBody(req);
        let body: unknown;
        try {
          body = raw ? JSON.parse(raw) : {};
        } catch {
          json(res, 400, { error: { code: 'BAD_REQUEST', message: 'body must be JSON' } });
          finish(400);
          return;
        }
        const parsed = parseWitnessRequest(body);
        const doc = await witness(parsed, deps);
        json(res, 200, doc);
        finish(200);
        return;
      }

      const claimMatch = url.pathname.match(/^\/claims\/([A-Za-z0-9_\-]{3,64})$/);
      if (req.method === 'GET' && claimMatch) {
        const doc = store.get(claimMatch[1]);
        if (!doc) {
          json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown claim id' } });
          finish(404);
          return;
        }
        json(res, 200, doc);
        finish(200);
        return;
      }

      const verifyMatch = url.pathname.match(/^\/claims\/([A-Za-z0-9_\-]{3,64})\/verify$/);
      if (req.method === 'GET' && verifyMatch) {
        const doc = store.get(verifyMatch[1]);
        if (!doc) {
          json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown claim id' } });
          finish(404);
          return;
        }
        const refetch = url.searchParams.get('refetch') === '1';
        const report = await buildVerifyReport(doc, refetch);
        json(res, 200, report);
        finish(200);
        return;
      }

      json(res, 404, { error: { code: 'NOT_FOUND', message: 'unknown route' } });
      finish(404);
    } catch (e) {
      if (e instanceof WitnessRequestError) {
        json(res, STATUS_FOR_CODE[e.code] ?? 400, { error: { code: e.code, message: e.message } });
        finish(STATUS_FOR_CODE[e.code] ?? 400);
        return;
      }
      if (e instanceof FetchError) {
        json(res, STATUS_FOR_CODE[e.code] ?? 502, { error: { code: e.code, message: e.message } });
        finish(STATUS_FOR_CODE[e.code] ?? 502);
        return;
      }
      if (e instanceof ExtractError) {
        json(res, 422, { error: { code: 'EXTRACT_FAILED', message: e.message } });
        finish(422);
        return;
      }
      log.error('unhandled error', { error: String((e as Error).stack ?? e).slice(0, 400) });
      json(res, 500, { error: { code: 'INTERNAL', message: 'internal error' } });
      finish(500);
    }
  });

  return {
    server,
    store,
    anchor,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.server.port, config.server.host, () => {
          const addr = server.address();
          resolve(typeof addr === 'object' && addr ? addr.port : config.server.port);
        });
      }),
  };
}

/** Exposed for tests. */
export const _internal = { canonicalJson };
