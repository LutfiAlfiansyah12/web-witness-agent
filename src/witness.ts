/**
 * The witness pipeline: validate request → SSRF-safe fetch → extract claim →
 * build signed core → commitment → Ed25519 signature → store → enqueue anchor.
 *
 * The agent NEVER fabricates: any fetch or extraction failure aborts the
 * pipeline with an error — no claim document is created.
 */
import { config } from './config.js';
import { fetchWitness, defaultFetchOptions } from './fetcher.js';
import { extractJsonPath, extractRegex, ExtractError } from './extract.js';
import {
  buildSignedCore,
  canonicalJson,
  computeCommitment,
  newClaimId,
  sha256Hex,
  type ClaimDoc,
  type WitnessRequest,
  type ExtractedClaim,
} from './claim.js';
import { signBytes } from './keys.js';
import type { ClaimStore } from './store.js';
import type { AnchorWorker } from './anchor.js';
import { log } from './log.js';

export class WitnessRequestError extends Error {
  code: string;
  constructor(code: string, msg: string) {
    super(msg);
    this.name = 'WitnessRequestError';
    this.code = code;
  }
}

export function parseWitnessRequest(body: unknown): WitnessRequest {
  if (typeof body !== 'object' || body === null) {
    throw new WitnessRequestError('BAD_REQUEST', 'JSON object expected');
  }
  const b = body as Record<string, unknown>;
  const url = b.url;
  if (typeof url !== 'string' || url.length === 0 || url.length > 2048) {
    throw new WitnessRequestError('BAD_REQUEST', '"url" must be a string of 1..2048 chars');
  }
  const mode = b.mode ?? 'jsonpath';
  if (mode !== 'jsonpath' && mode !== 'regex') {
    throw new WitnessRequestError('BAD_REQUEST', '"mode" must be "jsonpath" or "regex"');
  }
  const req: WitnessRequest = { url, mode };
  if (mode === 'jsonpath') {
    const p = b.path;
    if (typeof p !== 'string' || p.length === 0 || p.length > 256 || !/^[A-Za-z0-9_.\-]{1,256}$/.test(p)) {
      throw new WitnessRequestError(
        'BAD_REQUEST',
        'jsonpath mode requires "path": a dotted path of [A-Za-z0-9_.-], max 256 chars',
      );
    }
    req.path = p;
  } else {
    const re = b.regex;
    if (typeof re !== 'string' || re.length === 0 || re.length > 256) {
      throw new WitnessRequestError('BAD_REQUEST', 'regex mode requires "regex" (max 256 chars)');
    }
    req.regex = re;
    const g = typeof b.group === 'number' ? b.group : 0;
    if (!Number.isInteger(g) || g < 0 || g > 16) {
      throw new WitnessRequestError('BAD_REQUEST', '"group" must be an integer 0..16');
    }
    req.group = g;
  }
  return req;
}

export interface WitnessDeps {
  store: ClaimStore;
  anchor: AnchorWorker;
}

export async function witness(req: WitnessRequest, deps: WitnessDeps): Promise<ClaimDoc> {
  const opts = defaultFetchOptions();
  const fetched = await fetchWitness(req.url, opts);
  const text = fetched.bytes.toString('utf8');

  let claim: ExtractedClaim;
  if (req.mode === 'jsonpath') {
    const r = extractJsonPath(text, req.path!);
    claim = { mode: 'jsonpath', spec: req.path!, value: r.value };
  } else {
    const r = extractRegex(text, req.regex!, req.group ?? 0);
    claim = { mode: 'regex', spec: req.regex!, value: r.value };
  }

  const id = newClaimId();
  const createdAt = new Date().toISOString();
  const core = buildSignedCore(id, createdAt, req, {
    status: fetched.status,
    content_type: fetched.contentType,
    sha256: sha256Hex(fetched.bytes),
    size: fetched.bytes.length,
    fetched_at: createdAt,
    final_url: fetched.finalUrl,
  }, claim);
  // Sign the exact canonical bytes the commitment covers.
  const canonical = Buffer.from(canonicalJson(core), 'utf8');
  const commitment = sha256Hex(canonical);
  const signature = signBytes(canonical).toString('hex');

  const initialAnchor =
    config.anchor.mode === 'none'
      ? { status: 'disabled' as const }
      : { status: 'pending' as const, network: config.anchor.mode };

  const doc: ClaimDoc = {
    v: 1,
    id,
    created_at: createdAt,
    request: req,
    response: core.response,
    claim,
    commitment,
    signature,
    anchor: initialAnchor,
  };

  deps.store.put(doc);
  log.info('claim created', { id, url: req.url, commitment_prefix: commitment.slice(0, 16) });
  if (config.anchor.mode !== 'none') deps.anchor.enqueue(id);
  return doc;
}

export { ExtractError };
