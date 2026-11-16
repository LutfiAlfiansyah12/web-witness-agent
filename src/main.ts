/**
 * Entry point: load config, init keys, start the app.
 */
import { config } from './config.js';
import { setLogLevel, log } from './log.js';
import { initKeys } from './keys.js';
import { initApp } from './server.js';
import { AnchorWorker } from './anchor.js';

async function main(): Promise<void> {
  setLogLevel(config.logLevel);
  const keys = initKeys();

  const anchorAddress = await AnchorWorker.addressFromSeed(config.anchor.seed);
  const app = initApp();
  await app.listen();

  log.info('web-witness listening', {
    host: config.server.host,
    port: config.server.port,
    anchor_mode: config.anchor.mode,
    anchor_address: anchorAddress,
    public_key_prefix: keys.publicKeyHex.slice(0, 16),
  });

  if (config.anchor.mode !== 'none' && !config.anchor.seed) {
    log.warn('ANCHOR_MODE is set but ZKV_ANCHOR_SEED is empty — anchors will fail until configured');
  }
  if (config.fetch.allowPrivateTargets) {
    log.warn('ALLOW_PRIVATE_TARGETS=true — UNSAFE, for local tests only');
  }
}

void main();
