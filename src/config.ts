/**
 * Centralised configuration — everything comes from the environment.
 * Secrets are NEVER hardcoded; the anchor seed is read but never logged.
 */
import * as path from 'node:path';
import 'dotenv/config';

function opt(name: string, def: string): string {
  const v = process.env[name];
  return v && v.trim() !== '' ? v.trim() : def;
}

function num(name: string, def: number): number {
  const v = process.env[name];
  if (!v || v.trim() === '') return def;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`Env var ${name} must be a number, got ${v}`);
  return n;
}

function bool(name: string, def: boolean): boolean {
  const v = process.env[name];
  return v && v.trim() !== ''
    ? ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase())
    : def;
}

export type AnchorMode = 'none' | 'volta' | 'mainnet';

export const config = {
  server: {
    host: opt('HOST', '127.0.0.1'),
    port: num('PORT', 8082),
  },

  dataDir: path.resolve(opt('DATA_DIR', './data')),

  fetch: {
    maxBodyBytes: num('MAX_BODY_BYTES', 1048576),
    timeoutMs: num('FETCH_TIMEOUT_MS', 15000),
    maxRedirects: num('MAX_REDIRECTS', 3),
    // Unsafe, test-only escape hatch for loopback/private targets.
    allowPrivateTargets: bool('ALLOW_PRIVATE_TARGETS', false),
    allowHosts: opt('FETCH_ALLOW_HOSTS', '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    denyHosts: opt('FETCH_DENY_HOSTS', '')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  },

  rateLimit: {
    max: num('RATE_LIMIT_MAX', 10),
    windowMs: num('RATE_LIMIT_WINDOW_S', 60) * 1000,
    maxConcurrent: num('MAX_CONCURRENT_FETCHES', 4),
  },

  anchor: {
    mode: ((): AnchorMode => {
      const m = opt('ANCHOR_MODE', 'none');
      if (!['none', 'volta', 'mainnet'].includes(m)) {
        throw new Error(`Invalid ANCHOR_MODE: ${m}`);
      }
      return m as AnchorMode;
    })(),
    // Mnemonic or SURI for the remark-submitter account. Empty in none-mode.
    seed: process.env.ZKV_ANCHOR_SEED || '',
    rpcWss: opt('ZKV_RPC_WSS', 'wss://zkverify-volta-rpc.zkverify.io'),
    explorer: opt('ZKV_EXPLORER', 'https://zkverify-testnet.subscan.io/'),
    timeoutMs: num('ANCHOR_TIMEOUT_MS', 120000),
    pollMs: num('ANCHOR_POLL_MS', 6000),
  },

  logLevel: opt('LOG_LEVEL', 'info'),
};

export type Config = typeof config;
