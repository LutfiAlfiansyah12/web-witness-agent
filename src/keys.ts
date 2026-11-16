/**
 * Ed25519 signing key for claim documents. The keypair is generated on first
 * start and persisted under DATA_DIR (mode 0600). The public half is served
 * at GET /publickey so anyone can verify claim signatures offline.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { config } from './config.js';
import { log } from './log.js';

export interface AgentKeys {
  publicKeyHex: string; // 32-byte raw key, hex
  privateKeyPkcs8Hex: string;
  publicObj: crypto.KeyObject;
  privateObj: crypto.KeyObject;
}

let keys: AgentKeys | null = null;

function rawFromSpki(spki: Buffer): string {
  // SPKI for Ed25519 is 44 bytes; the raw key is the trailing 32.
  return spki.subarray(spki.length - 32).toString('hex');
}

function privateKeyFromPkcs8Hex(pkcs8Hex: string): crypto.KeyObject {
  const der = Buffer.from(pkcs8Hex, 'hex');
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

export function initKeys(): AgentKeys {
  if (keys) return keys;
  const file = path.join(config.dataDir, 'agent-ed25519.json');
  fs.mkdirSync(config.dataDir, { recursive: true });

  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as {
      public_key_hex: string;
      private_key_pkcs8_hex: string;
    };
    const privateObj = privateKeyFromPkcs8Hex(raw.private_key_pkcs8_hex);
    keys = {
      publicKeyHex: raw.public_key_hex,
      privateKeyPkcs8Hex: raw.private_key_pkcs8_hex,
      publicObj: crypto.createPublicKey(privateObj),
      privateObj,
    };
    log.info('agent signing key loaded', { public_key_sha_prefix: raw.public_key_hex.slice(0, 16) });
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyHex = rawFromSpki(publicKey.export({ type: 'spki', format: 'der' }));
    const privateKeyPkcs8Hex = privateKey
      .export({ type: 'pkcs8', format: 'der' })
      .toString('hex');
    keys = {
      publicKeyHex,
      privateKeyPkcs8Hex,
      publicObj: publicKey,
      privateObj: privateKey,
    };
    fs.writeFileSync(
      file,
      JSON.stringify({ public_key_hex: publicKeyHex, private_key_pkcs8_hex: privateKeyPkcs8Hex }, null, 2),
      { mode: 0o600 },
    );
    log.info('agent signing key generated', {
      file,
      public_key_sha_prefix: publicKeyHex.slice(0, 16),
    });
  }
  return keys;
}

export function getKeys(): AgentKeys {
  if (!keys) throw new Error('Keys not initialised — call initKeys() first');
  return keys;
}

export function signBytes(data: Buffer): Buffer {
  return crypto.sign(null, data, getKeys().privateObj);
}

export function verifyBytes(data: Buffer, sig: Buffer, publicKeyHex: string): boolean {
  const pub = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'), // Ed25519 SPKI prefix
      Buffer.from(publicKeyHex, 'hex'),
    ]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, data, pub, sig);
}
