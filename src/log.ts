/**
 * Structured logger with secret redaction. Never log the anchor seed,
 * private keys, or full signed headers.
 */
type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const REDACT_PATTERNS: RegExp[] = [
  /SEED|MNEMONIC|SURI/i,
  /PRIVATE_KEY|PRIVATE/i,
  /SIGNATURE|AUTHORIZATION/i,
];

function redactValue(v: unknown): unknown {
  if (typeof v === 'string') {
    // Heuristic: long hex strings that look like keys are not logged verbatim.
    if (/^[0-9a-fA-F]{96,}$/.test(v)) return `<redacted-hex:${v.length}>`;
    return v;
  }
  return v;
}

function redact(meta: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (REDACT_PATTERNS.some((p) => p.test(k))) {
      out[k] = '<redacted>';
    } else {
      out[k] = redactValue(v);
    }
  }
  return out;
}

let currentLevel: Level = 'info';

export function setLogLevel(level: string): void {
  if (level in LEVELS) currentLevel = level as Level;
}

function emit(level: Level, msg: string, meta?: Record<string, unknown>) {
  if (LEVELS[level] < LEVELS[currentLevel]) return;
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...(meta ? redact(meta) : {}),
  };
  const line = JSON.stringify(entry);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

export const log = {
  debug: (msg: string, meta?: Record<string, unknown>) => emit('debug', msg, meta),
  info: (msg: string, meta?: Record<string, unknown>) => emit('info', msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => emit('warn', msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => emit('error', msg, meta),
};
