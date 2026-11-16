/**
 * On-chain anchor worker — the zkVerify angle.
 *
 * Checkable claim: "the agent observed the data described by claim `id`, and
 * the SHA-256 commitment of that claim is anchored on zkVerify." The anchor
 * is a `system.remark` extrinsic whose payload is the self-describing string
 *
 *     webwitness/v1/<commitment-hex>
 *
 * Anyone can look the remark up on the block explorer (Subscan) and compare
 * it byte-for-byte with the `commitment` field of the claim document — and
 * independently recompute that commitment from the claim itself.
 *
 * Anchoring runs asynchronously: witness responses return immediately with
 * anchor.status "pending"; the worker updates the store as the extrinsic
 * reaches a finalized block. One job at a time; @polkadot/api is loaded
 * lazily so tests and no-anchor deployments never touch it.
 */
import { config } from './config.js';
import { log } from './log.js';
import type { ClaimStore } from './store.js';

export function remarkFor(commitment: string): string {
  return `webwitness/v1/${commitment}`;
}

export class AnchorWorker {
  private queue: string[] = [];
  private running = false;
  private store: ClaimStore | null = null;

  start(store: ClaimStore): void {
    this.store = store;
  }

  enqueue(claimId: string): void {
    if (!this.store) throw new Error('AnchorWorker not started');
    this.queue.push(claimId);
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.running || !this.store) return;
    this.running = true;
    try {
      while (this.queue.length > 0) {
        const id = this.queue.shift()!;
        await this.anchorOne(id).catch((e: Error) => {
          log.error('anchor job crashed', { id, error: String(e.message).slice(0, 160) });
          this.store!.updateAnchor(id, { status: 'failed', error: String(e.message).slice(0, 200) });
        });
      }
    } finally {
      this.running = false;
    }
  }

  private async anchorOne(id: string): Promise<void> {
    const store = this.store!;
    const doc = store.get(id);
    if (!doc || doc.anchor.status === 'disabled') return;

    if (!config.anchor.seed) {
      store.updateAnchor(id, {
        status: 'failed',
        error: 'ZKV_ANCHOR_SEED is not configured',
      });
      return;
    }

    const remark = remarkFor(doc.commitment);
    store.updateAnchor(id, { status: 'submitted', network: config.anchor.mode, remark });

    // Lazy-load the (heavy) Substrate stack only when actually anchoring.
    const { ApiPromise, WsProvider } = await import('@polkadot/api');
    const api = await ApiPromise.create({
      provider: new WsProvider(config.anchor.rpcWss),
    });

    try {
      const keyring = await import('@polkadot/keyring').then((m) => new m.Keyring({ type: 'sr25519' }));
      const pair = keyring.addFromUri(config.anchor.seed);

      const result = await Promise.race([
        (async () => {
          return new Promise<{ txHash: string; blockHash: string; blockNumber: number }>(
            (resolve, reject) => {
              let unsub: (() => void) | undefined;
              void api.tx.system
                .remark(remark)
                .signAndSend(pair, (res) => {
                  if (res.isError) {
                    unsub?.();
                    reject(new Error(`extrinsic errored: ${String(res.dispatchError ?? 'unknown').slice(0, 160)}`));
                  } else if (res.status.isFinalized) {
                    unsub?.();
                    resolve({
                      txHash: res.txHash.toHex(),
                      blockHash: res.status.asFinalized.toHex(),
                      blockNumber: 0,
                    });
                  }
                })
                .then((u) => {
                  unsub = u;
                })
                .catch(reject);
            },
          );
        })(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('anchor deadline exceeded')), config.anchor.timeoutMs),
        ),
      ]);

      const header = await api.rpc.chain.getHeader(result.blockHash);
      const blockNumber = header.number.toNumber();
      const explorerUrl = `${config.anchor.explorer.replace(/\/+$/, '')}/extrinsic/${result.txHash}`;

      store.updateAnchor(id, {
        status: 'finalized',
        network: config.anchor.mode,
        remark,
        tx_hash: result.txHash,
        block_hash: result.blockHash,
        explorer_url: explorerUrl,
      });
      log.info('anchor finalized', { id, block: blockNumber, tx: result.txHash.slice(0, 18) + '…' });
    } finally {
      await api.disconnect();
    }
  }

  /** Resolve the anchor account address without spending anything. */
  static async addressFromSeed(seed: string): Promise<string | null> {
    if (!seed) return null;
    try {
      const { Keyring } = await import('@polkadot/keyring');
      const keyring = new Keyring({ type: 'sr25519' });
      return keyring.addFromUri(seed).address;
    } catch {
      return null;
    }
  }
}
