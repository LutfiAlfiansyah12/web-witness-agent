/**
 * Persistent claim store — a single JSON file under DATA_DIR.
 * Writes are atomic (tmp + rename). Volume is small by design: claims are
 * compact documents, not payload archives.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ClaimDoc, AnchorInfo } from './claim.js';
import { log } from './log.js';

export class ClaimStore {
  private file: string;
  private docs = new Map<string, ClaimDoc>();

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.file = path.join(dataDir, 'claims.json');
    this.load();
  }

  private load(): void {
    if (!fs.existsSync(this.file)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8')) as { claims?: ClaimDoc[] };
      for (const doc of raw.claims ?? []) this.docs.set(doc.id, doc);
      log.info('claim store loaded', { count: this.docs.size });
    } catch (e) {
      log.error('claim store load failed — starting empty', { error: String(e).slice(0, 120) });
    }
  }

  private save(): void {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ claims: [...this.docs.values()] }, null, 2));
    fs.renameSync(tmp, this.file);
  }

  put(doc: ClaimDoc): void {
    this.docs.set(doc.id, doc);
    this.save();
  }

  get(id: string): ClaimDoc | undefined {
    return this.docs.get(id);
  }

  updateAnchor(id: string, anchor: AnchorInfo): ClaimDoc | undefined {
    const doc = this.docs.get(id);
    if (!doc) return undefined;
    doc.anchor = { ...anchor, updated_at: new Date().toISOString() };
    this.save();
    return doc;
  }

  get size(): number {
    return this.docs.size;
  }
}
