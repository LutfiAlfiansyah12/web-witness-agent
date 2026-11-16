/**
 * SSRF-hardened outbound fetcher.
 *
 * The agent fetches arbitrary user-supplied URLs — the classic SSRF posture.
 * Hardening:
 *   - only http/https schemes, no embedded credentials;
 *   - every hop's hostname is resolved (all A/AAAA records) and rejected if
 *     ANY address is loopback/private/reserved/link-local (incl. cloud
 *     metadata 169.254.169.254 and IPv4-mapped IPv6);
 *   - redirects are followed manually and re-validated hop by hop;
 *   - response bodies are streamed with a hard byte cap;
 *   - global wall-clock timeout across all hops;
 *   - optional allow/deny host lists.
 *
 * allowPrivateTargets exists ONLY for the local test harness.
 */
import * as dns from 'node:dns';
import { config } from './config.js';
import { log } from './log.js';

export class FetchError extends Error {
  code: string;
  constructor(code: string, msg: string) {
    super(msg);
    this.name = 'FetchError';
    this.code = code;
  }
}

export interface FetchOptions {
  maxBodyBytes: number;
  timeoutMs: number;
  maxRedirects: number;
  allowPrivateTargets: boolean;
  allowHosts: string[];
  denyHosts: string[];
}

export function defaultFetchOptions(): FetchOptions {
  return {
    maxBodyBytes: config.fetch.maxBodyBytes,
    timeoutMs: config.fetch.timeoutMs,
    maxRedirects: config.fetch.maxRedirects,
    allowPrivateTargets: config.fetch.allowPrivateTargets,
    allowHosts: config.fetch.allowHosts,
    denyHosts: config.fetch.denyHosts,
  };
}

export interface FetchedResponse {
  finalUrl: string;
  status: number;
  contentType: string;
  bytes: Buffer;
}

// ── IP classification ────────────────────────────────────────────────────────

function ipv4IsPrivate(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  const [a, b] = p;
  if (a === 0) return true; // "this network"
  if (a === 10) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 0 && (p[2] === 0 || p[2] === 2)) return true; // v6 transition / TEST-NET-1
  if (a === 192 && b === 168) return true; // private
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && p[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && p[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function ipIsPrivate(ip: string): boolean {
  if (ip.includes('.') && !ip.includes(':')) return ipv4IsPrivate(ip);
  const low = ip.toLowerCase();
  // IPv4-mapped / translated IPv6 must be judged by the embedded IPv4.
  const mapped = low.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4IsPrivate(mapped[1]);
  if (low === '::' || low === '::1') return true;
  if (low.startsWith('fc') || low.startsWith('fd')) return true; // ULA fc00::/7
  if (low.startsWith('fe8') || low.startsWith('fe9') || low.startsWith('fea') || low.startsWith('feb')) {
    return true; // link-local fe80::/10
  }
  if (low.startsWith('ff')) return true; // multicast
  if (low.startsWith('64:ff9b:') || low.startsWith('::ffff:0:')) return true; // NAT64/translated
  return false;
}

// ── URL validation ───────────────────────────────────────────────────────────

function hostMatchesList(host: string, list: string[]): boolean {
  return list.some((entry) =>
    entry.startsWith('*') ? host.endsWith(entry.slice(1)) : host === entry,
  );
}

export function validateTarget(rawUrl: string, opts: FetchOptions): URL {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new FetchError('INVALID_URL', 'not a parseable URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new FetchError('INVALID_URL', 'only http/https schemes are allowed');
  }
  if (u.username || u.password) {
    throw new FetchError('INVALID_URL', 'embedded credentials are not allowed');
  }
  if (u.hostname.length === 0 || u.hostname.length > 253) {
    throw new FetchError('INVALID_URL', 'invalid hostname length');
  }
  const host = u.hostname.toLowerCase();
  if (opts.denyHosts.length > 0 && hostMatchesList(host, opts.denyHosts)) {
    throw new FetchError('BLOCKED_TARGET', 'host is deny-listed');
  }
  if (opts.allowHosts.length > 0 && !hostMatchesList(host, opts.allowHosts)) {
    throw new FetchError('BLOCKED_TARGET', 'host is not on the allow-list');
  }
  return u;
}

/** Resolve every A/AAAA record and reject if ANY is non-public. */
async function resolveAndCheck(hostname: string, opts: FetchOptions): Promise<void> {
  const host = hostname.toLowerCase();
  if (opts.allowPrivateTargets) return;
  let records: dns.LookupAddress[];
  try {
    records = await dns.promises.lookup(host, { all: true, verbatim: true });
  } catch {
    throw new FetchError('DNS_FAILURE', `cannot resolve host ${host}`);
  }
  if (records.length === 0) {
    throw new FetchError('DNS_FAILURE', `no addresses for host ${host}`);
  }
  for (const r of records) {
    if (ipIsPrivate(r.address)) {
      log.warn('ssrf guard rejected private address', { host, family: r.family });
      throw new FetchError('BLOCKED_TARGET', 'host resolves to a private/reserved address');
    }
  }
}

// ── Body reading with hard cap ───────────────────────────────────────────────

async function readBodyCapped(res: Response, cap: number): Promise<Buffer> {
  const declared = res.headers.get('content-length');
  if (declared && Number(declared) > cap) {
    throw new FetchError('BODY_TOO_LARGE', `declared body ${declared} bytes exceeds cap ${cap}`);
  }
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel().catch(() => {});
        throw new FetchError('BODY_TOO_LARGE', `body exceeded cap of ${cap} bytes`);
      }
      chunks.push(Buffer.from(value));
    }
  }
  return Buffer.concat(chunks);
}

// ── Main entry ───────────────────────────────────────────────────────────────

export async function fetchWitness(rawUrl: string, opts?: FetchOptions): Promise<FetchedResponse> {
  const o = opts ?? defaultFetchOptions();
  const deadline = Date.now() + o.timeoutMs;
  let current = validateTarget(rawUrl, o);

  for (let hop = 0; ; hop++) {
    await resolveAndCheck(current.hostname, o);
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new FetchError('TIMEOUT', 'fetch deadline exceeded before request');
    }

    const res = await fetch(current.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(remaining),
      headers: { 'user-agent': 'WebWitnessAgent/1.0 (+claim verification)', accept: '*/*' },
    }).catch((e: Error) => {
      if (e.name === 'TimeoutError' || e.name === 'AbortError') {
        throw new FetchError('TIMEOUT', 'fetch timed out');
      }
      throw new FetchError('FETCH_FAILED', `network error: ${e.message.slice(0, 120)}`);
    });

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new FetchError('FETCH_FAILED', 'redirect without Location header');
      if (hop >= o.maxRedirects) {
        throw new FetchError('TOO_MANY_REDIRECTS', `more than ${o.maxRedirects} redirects`);
      }
      const next = validateTarget(new URL(loc, current).toString(), o);
      if (next.protocol !== current.protocol && next.protocol === 'http:') {
        log.info('redirect downgrades to http', { to: next.hostname });
      }
      current = next;
      continue;
    }

    const bytes = await readBodyCapped(res, o.maxBodyBytes);
    return {
      finalUrl: current.toString(),
      status: res.status,
      contentType: res.headers.get('content-type') ?? '',
      bytes,
    };
  }
}
