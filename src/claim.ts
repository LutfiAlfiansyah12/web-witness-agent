/**
 * Claim documents — the signed statement of what the agent observed.
 *
 * A claim doc has a SIGNED CORE (everything except signature and anchor):
 *
 *   { v, id, created_at, request, response, claim }
 *
 *   commitment = SHA-256(canonicalJson(core))
 *   signature  = Ed25519(canonicalJson(core))
 *
 * Both the signature and the commitment are independently recomputable by
 * anyone from the public doc. The commitment hex string is exactly what gets
 * anchored on zkVerify (system.remark), binding the claim to the chain.
 */
import * as crypto from 'node:crypto';
import { verifyBytes } from './keys.js';

export interface WitnessRequest {
  url: string;
  mode: 'jsonpath' | 'regex';
  path?: string; // jsonpath mode: dotted path, e.g. "data.amount" or "items.0.price"
  regex?: string; // regex mode
  group?: number; // regex capture group (default 0)
}

export interface ObservedResponse {
  status: number;
  content_type: string;
  sha256: string; // hex over the EXACT response body bytes
  size: number;
  fetched_at: string; // ISO timestamp
  final_url: string; // after redirects
}

export interface ExtractedClaim {
  mode: 'jsonpath' | 'regex';
  spec: string; // the path or the regex actually applied
  value: string | number | boolean | null;
}

export interface AnchorInfo {
  status: 'disabled' | 'pending' | 'submitted' | 'finalized' | 'failed';
  network?: string;
  remark?: string;
  tx_hash?: string;
  block_hash?: string;
  explorer_url?: string;
  error?: string;
  updated_at?: string;
}

export interface ClaimDoc {
  v: 1;
  id: string;
  created_at: string;
  request: WitnessRequest;
  response: ObservedResponse;
  claim: ExtractedClaim;
  commitment: string;
  signature: string; // Ed25519 hex over canonicalJson(core)
  anchor: AnchorInfo;
}

export type SignedCore = Pick<ClaimDoc, 'v' | 'id' | 'created_at' | 'request' | 'response' | 'claim'>;

/** Deterministic JSON: keys sorted recursively, no insignificant whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function buildSignedCore(
  id: string,
  created_at: string,
  request: WitnessRequest,
  response: ObservedResponse,
  claim: ExtractedClaim,
): SignedCore {
  return { v: 1, id, created_at, request, response, claim };
}

/** commitment = SHA-256 over the canonical core. */
export function computeCommitment(core: SignedCore): string {
  return sha256Hex(canonicalJson(core));
}

export function newClaimId(): string {
  return `wit_${crypto.randomBytes(8).toString('hex')}`;
}

export function claimCore(doc: ClaimDoc): SignedCore {
  const { v, id, created_at, request, response, claim } = doc;
  return { v, id, created_at, request, response, claim };
}

/**
 * Full offline verification of a claim doc against a public key:
 *  1. recompute the commitment from the core;
 *  2. verify the Ed25519 signature over the canonical core.
 */
export function verifyClaimDoc(
  doc: ClaimDoc,
  publicKeyHex: string,
): { signature_valid: boolean; commitment_matches: boolean } {
  const core = claimCore(doc);
  const recomputed = computeCommitment(core);
  const sigOk = verifyBytes(
    Buffer.from(canonicalJson(core), 'utf8'),
    Buffer.from(doc.signature, 'hex'),
    publicKeyHex,
  );
  return { signature_valid: sigOk, commitment_matches: recomputed === doc.commitment };
}
