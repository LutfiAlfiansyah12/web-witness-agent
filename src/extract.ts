/**
 * Extraction of a claim from an observed response body.
 *
 * Two modes:
 *  - jsonpath: a dotted path into a parsed JSON document ("data.amount",
 *    "items.0.price" — numeric segments index arrays).
 *  - regex: a regular expression over the UTF-8 text, capturing a group.
 *
 * The agent never fabricates a value: a missing path or non-matching regex
 * is an error, not an empty claim.
 */

export interface ExtractResult {
  value: string | number | boolean | null;
}

export class ExtractError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'ExtractError';
  }
}

const MAX_JSON_DEPTH = 32;

export function extractJsonPath(text: string, path: string): ExtractResult {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new ExtractError('response body is not valid JSON');
  }
  const segments = path.split('.').filter((s) => s.length > 0);
  if (segments.length === 0) throw new ExtractError('empty path');

  let cur: unknown = doc;
  for (let i = 0; i < segments.length; i++) {
    if (i > MAX_JSON_DEPTH) throw new ExtractError('path too deep');
    const seg = segments[i];
    if (cur === null || typeof cur !== 'object') {
      throw new ExtractError(`path segment "${seg}" reached a non-object`);
    }
    const obj = cur as Record<string, unknown>;
    if (Array.isArray(obj)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= obj.length) {
        throw new ExtractError(`array index "${seg}" out of range`);
      }
      cur = obj[idx];
    } else if (!(seg in obj)) {
      throw new ExtractError(`path segment "${seg}" not found`);
    } else {
      cur = obj[seg];
    }
  }
  if (cur === undefined) throw new ExtractError('path resolved to undefined');
  if (cur !== null && typeof cur === 'object') {
    throw new ExtractError('path resolved to an object/array — claims must be scalars');
  }
  return { value: cur as string | number | boolean | null };
}

export function extractRegex(text: string, pattern: string, group = 0): ExtractResult {
  if (pattern.length > 256) throw new ExtractError('regex longer than 256 chars');
  if (group > 16) throw new ExtractError('group index too large');
  let re: RegExp;
  try {
    re = new RegExp(pattern, 's');
  } catch {
    throw new ExtractError('invalid regular expression');
  }
  const m = re.exec(text);
  if (!m) throw new ExtractError('regex did not match');
  if (group > (m.length - 1)) throw new ExtractError(`capture group ${group} does not exist`);
  const val = m[group];
  if (val === undefined) throw new ExtractError(`capture group ${group} is empty`);
  return { value: val };
}
