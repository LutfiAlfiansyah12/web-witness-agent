/**
 * End-to-end local harness. No network, no secrets, no on-chain access:
 * every outbound fetch stays on 127.0.0.1 against the fixture server, and
 * ANCHOR_MODE=none keeps @polkadot/api untouched.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { config } from '../src/config.js';
import { initKeys, getKeys, verifyBytes, signBytes } from '../src/keys.js';
import {
  canonicalJson,
  buildSignedCore,
  computeCommitment,
  verifyClaimDoc,
  sha256Hex,
  newClaimId,
  type ClaimDoc,
} from '../src/claim.js';
import { extractJsonPath, extractRegex, ExtractError } from '../src/extract.js';
import { fetchWitness, defaultFetchOptions, FetchError } from '../src/fetcher.js';
import { ClaimStore } from '../src/store.js';
import { witness, parseWitnessRequest, WitnessRequestError } from '../src/witness.js';
import { AnchorWorker } from '../src/anchor.js';
import { initApp } from '../src/server.js';
import { startFixture, type Fixture } from './fixtures.js';

let passed = 0;
let failed = 0;

function check(name: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.error(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function expectFetchError(name: string, p: Promise<unknown>, code: string): Promise<void> {
  try {
    await p;
    check(name, false, `expected FetchError ${code}, got success`);
  } catch (e) {
    check(name, e instanceof FetchError && e.code === code, `got ${(e as Error).message}`);
  }
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'webwitness-test-'));
}

async function main(): Promise<void> {
  const fixture = await startFixture();

  // ── canonicalJson ────────────────────────────────────────────────────────
  console.log('\n[canonical JSON]');
  const a = { b: 2, a: 1, nested: { y: 2, x: 1 } };
  const b = { a: 1, b: 2, nested: { x: 1, y: 2 } };
  check('key order does not matter', canonicalJson(a) === canonicalJson(b));
  check('compact output', canonicalJson(a) === '{"a":1,"b":2,"nested":{"x":1,"y":2}}');
  check(
    'arrays keep order',
    canonicalJson([{ k: 1 }, { k: 2 }]) === '[{"k":1},{"k":2}]',
  );

  // ── keys ─────────────────────────────────────────────────────────────────
  console.log('\n[Ed25519 keys]');
  config.dataDir = tmpDir();
  initKeys();
  const pub = getKeys().publicKeyHex;
  check('public key is 32-byte hex', /^[0-9a-f]{64}$/.test(pub));
  const msg = Buffer.from('hello claims');
  const sig = signBytes(msg);
  check('signature verifies', verifyBytes(msg, sig, pub));
  check('tampered message rejected', !verifyBytes(Buffer.from('hello claimz'), sig, pub));

  // ── claim core / commitment ──────────────────────────────────────────────
  console.log('\n[claim core + commitment]');
  const req = { url: fixture.url('/json'), mode: 'jsonpath' as const, path: 'data.amount' };
  const core = buildSignedCore(newClaimId(), '2026-11-17T00:00:00.000Z', req, {
    status: 200,
    content_type: 'application/json',
    sha256: sha256Hex(JSON.stringify({})),
    size: 2,
    fetched_at: '2026-11-17T00:00:00.000Z',
    final_url: fixture.url('/json'),
  }, { mode: 'jsonpath', spec: 'data.amount', value: 97412.34 });
  const commitment = computeCommitment(core);
  check('commitment is 64 hex', /^[0-9a-f]{64}$/.test(commitment));
  check('commitment deterministic', computeCommitment(core) === commitment);
  const doc: ClaimDoc = {
    ...core,
    commitment,
    signature: signBytes(Buffer.from(canonicalJson(core), 'utf8')).toString('hex'),
    anchor: { status: 'disabled' },
  };
  const v = verifyClaimDoc(doc, pub);
  check('verifyClaimDoc: signature ok', v.signature_valid);
  check('verifyClaimDoc: commitment ok', v.commitment_matches);
  const tampered: ClaimDoc = { ...doc, claim: { ...doc.claim, value: 1 } };
  const vt = verifyClaimDoc(tampered, pub);
  check('tampered claim value detected', !vt.signature_valid && !vt.commitment_matches);

  // ── extraction ───────────────────────────────────────────────────────────
  console.log('\n[extraction]');
  const jsonText = JSON.stringify({ data: { amount: 42 }, items: [{ price: 5 }, { price: 7 }] });
  check('jsonpath nested', extractJsonPath(jsonText, 'data.amount').value === 42);
  check('jsonpath array index', extractJsonPath(jsonText, 'items.1.price').value === 7);
  check('jsonpath null value', extractJsonPath('{"n":null}', 'n').value === null);
  let threw = false;
  try { extractJsonPath(jsonText, 'data.missing'); } catch (e) { threw = e instanceof ExtractError; }
  check('missing path errors', threw);
  threw = false;
  try { extractJsonPath(jsonText, 'items'); } catch (e) { threw = e instanceof ExtractError; }
  check('object result errors (claims must be scalars)', threw);
  check('regex capture', extractRegex('Price: EUR 42.50 today', 'EUR (\\d+\\.\\d+)', 1).value === '42.50');
  threw = false;
  try { extractRegex('nothing here', 'EUR (\\d+)'); } catch (e) { threw = e instanceof ExtractError; }
  check('regex non-match errors', threw);

  // ── fetcher: positive + SSRF negatives ───────────────────────────────────
  console.log('\n[fetcher / SSRF guard]');
  const pubOpts = { ...defaultFetchOptions(), allowPrivateTargets: true };
  const good = await fetchWitness(fixture.url('/json'), pubOpts);
  check('fixture fetch ok', good.status === 200 && good.bytes.length > 0);
  check('content-type captured', good.contentType.includes('application/json'));

  const redirect = await fetchWitness(fixture.url('/redirect'), pubOpts);
  check('redirect followed (≤3 hops)', redirect.finalUrl.endsWith('/json'));

  await expectFetchError(
    'loopback target blocked when private targets disallowed',
    fetchWitness(fixture.url('/json'), { ...pubOpts, allowPrivateTargets: false }),
    'BLOCKED_TARGET',
  );
  await expectFetchError(
    'metadata IP blocked (169.254.169.254)',
    fetchWitness('http://169.254.169.254/latest/meta-data/', { ...pubOpts, allowPrivateTargets: false }),
    'BLOCKED_TARGET',
  );
  await expectFetchError(
    'ftp scheme rejected',
    fetchWitness('ftp://example.com/x', pubOpts),
    'INVALID_URL',
  );
  await expectFetchError(
    'embedded credentials rejected',
    fetchWitness('http://user:pass@example.com/x', pubOpts),
    'INVALID_URL',
  );
  await expectFetchError(
    'redirect loop hits max redirects',
    fetchWitness(fixture.url('/redirect-loop'), pubOpts),
    'TOO_MANY_REDIRECTS',
  );
  await expectFetchError(
    'body over cap rejected',
    fetchWitness(fixture.url('/big'), { ...pubOpts, maxBodyBytes: 1024 }),
    'BODY_TOO_LARGE',
  );
  await expectFetchError(
    'deny-list host rejected',
    fetchWitness(fixture.url('/json'), { ...pubOpts, denyHosts: ['*'] }),
    'BLOCKED_TARGET',
  );

  // ── store ────────────────────────────────────────────────────────────────
  console.log('\n[store]');
  const storeDir = tmpDir();
  const store1 = new ClaimStore(storeDir);
  store1.put(doc);
  const store2 = new ClaimStore(storeDir);
  check('claim persists across instances', store2.get(doc.id)?.commitment === commitment);
  const upd = store2.updateAnchor(doc.id, { status: 'finalized', tx_hash: '0xabc' });
  check('anchor update persists', new ClaimStore(storeDir).get(doc.id)?.anchor.tx_hash === '0xabc' && upd !== undefined);

  // ── witness pipeline (module level) ──────────────────────────────────────
  console.log('\n[witness pipeline]');
  config.dataDir = tmpDir();
  initKeys();
  config.fetch.allowPrivateTargets = true;
  const anchor = new AnchorWorker();
  const store = new ClaimStore(config.dataDir);
  anchor.start(store);
  const deps = { store, anchor };
  const preq = parseWitnessRequest({ url: fixture.url('/json'), mode: 'jsonpath', path: 'data.amount' });
  const claimDoc = await witness(preq, deps);
  check('claim id prefix', claimDoc.id.startsWith('wit_'));
  check('claimed value', claimDoc.claim.value === 97412.34);
  check('response sha256 matches direct hash', claimDoc.response.sha256 === sha256Hex((await fetchWitness(fixture.url('/json'), pubOpts)).bytes));
  check('anchor disabled in none-mode', claimDoc.anchor.status === 'disabled');
  const vfull = verifyClaimDoc(claimDoc, getKeys().publicKeyHex);
  check('e2e claim self-verifies', vfull.signature_valid && vfull.commitment_matches);
  check('remark embeds commitment', (await import('../src/anchor.js')).remarkFor('abc') === 'webwitness/v1/abc');

  let reqErr = false;
  try { parseWitnessRequest({ url: fixture.url('/json'), mode: 'jsonpath' }); } catch (e) { reqErr = e instanceof WitnessRequestError; }
  check('jsonpath without path rejected', reqErr);

  // ── HTTP surface (end-to-end over the real server) ───────────────────────
  console.log('\n[HTTP surface]');
  config.dataDir = tmpDir();
  initKeys();
  config.server.port = 0;
  config.rateLimit.max = 1000; // rate-limit tested separately
  const app = initApp();
  const port = await app.listen();
  const base = `http://127.0.0.1:${port}`;

  const home = await fetch(base + '/');
  check('GET / serves demo page', home.status === 200 && (await home.text()).includes('Web'));

  const health = await (await fetch(base + '/healthz')).json();
  check('healthz ok', (health as { ok: boolean }).ok === true);

  const pk = await (await fetch(base + '/publickey')).json();
  check('publickey matches initKeys', (pk as { public_key_hex: string }).public_key_hex === getKeys().publicKeyHex);

  const witRes = await fetch(base + '/witness', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: fixture.url('/json'), mode: 'jsonpath', path: 'data.amount' }),
  });
  check('POST /witness 200', witRes.status === 200);
  const witDoc = (await witRes.json()) as ClaimDoc;
  check('claim over HTTP is verifiable', verifyClaimDoc(witDoc, getKeys().publicKeyHex).signature_valid);

  const refetched = await (await fetch(`${base}/claims/${witDoc.id}/verify?refetch=1`)).json();
  check('verify report: refetch value matches', (refetched as { refetch: { value_matches: boolean } }).refetch.value_matches === true);
  check('verify report: commitment matches', (refetched as { commitment: { matches: boolean } }).commitment.matches === true);

  const rep = await (await fetch(`${base}/claims/${witDoc.id}`)).json();
  check('GET /claims/:id returns doc', (rep as { id: string }).id === witDoc.id);

  const notFound = await fetch(base + '/claims/wit_unknown');
  check('unknown claim 404', notFound.status === 404);

  const badUrl = await fetch(base + '/witness', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'ftp://x', mode: 'jsonpath', path: 'a' }),
  });
  check('bad scheme 400', badUrl.status === 400);

  const missing = await fetch(base + '/witness', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: fixture.url('/json'), mode: 'jsonpath' }),
  });
  check('jsonpath missing path 400', missing.status === 400);

  const noExtract = await fetch(base + '/witness', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: fixture.url('/json'), mode: 'jsonpath', path: 'data.currency' }),
  });
  check('extraction of currency works', noExtract.status === 200 && ((await noExtract.json()) as { claim: { value: string } }).claim.value === 'BTC');

  // rate limit: fresh bucket via a fresh process-wide map would be needed;
  // instead hammer one IP until capped.
  config.rateLimit.max = 2;
  config.rateLimit.windowMs = 60000;
  const responses: number[] = [];
  for (let i = 0; i < 4; i++) {
    responses.push(
      (
        await fetch(base + '/witness', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url: fixture.url('/json'), mode: 'jsonpath', path: 'ok' }),
        })
      ).status,
    );
  }
  check('rate limiter caps at max', responses.includes(429), `statuses: ${responses.join(',')}`);

  app.server.close();
  fixture.close();

  console.log(`\n════════════════════════════════════`);
  console.log(`  ${passed} passed, ${failed} failed`);
  console.log(`════════════════════════════════════`);
  if (failed > 0) process.exitCode = 1;
}

void main().catch((e) => {
  console.error('HARNESS CRASH:', e);
  process.exitCode = 1;
});
