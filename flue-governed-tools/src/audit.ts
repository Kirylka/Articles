/**
 * Tamper-evident, hash-chained audit log.
 *
 * Every governed tool call appends exactly one entry. Each entry stores the
 * SHA-256 hash of the previous entry, so the log forms a chain: altering or
 * removing any historical entry breaks every hash after it, which
 * {@link verifyChain} detects. The genesis entry chains from 64 zeros.
 *
 * Entries are serialized as canonical JSON (recursively key-sorted) so the
 * hash is stable regardless of property insertion order.
 */

import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { dirname } from "node:path";
import type { Decision, Outcome } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

/** A single, immutable record of a governed tool call. */
export interface AuditEntry {
  seq: number;
  ts: string;
  prevHash: string;
  actorId: string;
  tenantId: string;
  tool: string;
  decision: Decision;
  outcome: Outcome;
  requestedScopes: string[];
  requestId?: string;
  idempotencyKey?: string;
  /** Approver id, when the call passed through an approval adapter. */
  approver?: string;
  /** Redacted arguments. */
  args?: unknown;
  /** Redacted result, present on success/replay. */
  result?: unknown;
  /** Error code or message, present on denial/error. */
  error?: string;
  /** SHA-256 of all fields above (canonicalized), including `prevHash`. */
  hash: string;
}

/** The fields of an entry that are hashed (everything except `hash`). */
export type AuditEntryBody = Omit<AuditEntry, "hash">;

/** Recursively sort object keys so serialization is deterministic. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Compute the chain hash for an entry body. When `hmacKey` is provided the hash
 * is an HMAC-SHA256 keyed with it, which additionally defends against an
 * attacker who can rewrite the entire file from genesis (they cannot forge a
 * valid chain without the key). Without a key it is a plain SHA-256.
 */
export function hashEntry(body: AuditEntryBody, hmacKey?: string): string {
  const json = JSON.stringify(canonicalize(body));
  const hasher = hmacKey
    ? createHmac("sha256", hmacKey)
    : createHash("sha256");
  return hasher.update(json).digest("hex");
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * Web Crypto (SubtleCrypto) variant of {@link hashEntry}, for runtimes that
 * expose `crypto.subtle` but not `node:crypto` — e.g. Cloudflare Workers and
 * other edge runtimes. Produces byte-identical hashes to {@link hashEntry}, so
 * the two are interchangeable on the same chain.
 */
export async function hashEntryAsync(
  body: AuditEntryBody,
  hmacKey?: string,
): Promise<string> {
  const json = JSON.stringify(canonicalize(body));
  const data = new TextEncoder().encode(json);
  const subtle = globalThis.crypto.subtle;
  if (hmacKey) {
    const key = await subtle.importKey(
      "raw",
      new TextEncoder().encode(hmacKey),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return toHex(await subtle.sign("HMAC", key, data));
  }
  return toHex(await subtle.digest("SHA-256", data));
}

/** What a caller provides; the log fills in seq, prevHash, ts and hash. */
export type AuditInput = Omit<AuditEntryBody, "seq" | "prevHash" | "ts"> & {
  ts?: string;
};

export interface AuditLog {
  /** Append an entry and return the fully-populated, hashed record. */
  append(input: AuditInput): Promise<AuditEntry>;
  /** All entries, in order. */
  entries(): Promise<AuditEntry[]>;
}

/**
 * Walk a chain and report the first inconsistency, if any. Pass the same
 * `hmacKey` the log was written with (if any) or verification will fail.
 */
export function verifyChain(
  entries: AuditEntry[],
  hmacKey?: string,
): {
  valid: boolean;
  brokenAt?: number;
  reason?: string;
} {
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    if (entry.seq !== i) {
      return { valid: false, brokenAt: i, reason: `seq mismatch at index ${i}` };
    }
    if (entry.prevHash !== prevHash) {
      return { valid: false, brokenAt: i, reason: `prevHash mismatch at seq ${i}` };
    }
    const { hash, ...body } = entry;
    if (hashEntry(body, hmacKey) !== hash) {
      return { valid: false, brokenAt: i, reason: `content hash mismatch at seq ${i}` };
    }
    prevHash = hash;
  }
  return { valid: true };
}

/** {@link verifyChain} using Web Crypto, for edge runtimes (see {@link hashEntryAsync}). */
export async function verifyChainAsync(
  entries: AuditEntry[],
  hmacKey?: string,
): Promise<{ valid: boolean; brokenAt?: number; reason?: string }> {
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i]!;
    if (entry.seq !== i) {
      return { valid: false, brokenAt: i, reason: `seq mismatch at index ${i}` };
    }
    if (entry.prevHash !== prevHash) {
      return { valid: false, brokenAt: i, reason: `prevHash mismatch at seq ${i}` };
    }
    const { hash, ...body } = entry;
    if ((await hashEntryAsync(body, hmacKey)) !== hash) {
      return { valid: false, brokenAt: i, reason: `content hash mismatch at seq ${i}` };
    }
    prevHash = hash;
  }
  return { valid: true };
}

/** In-memory audit log, useful for tests and ephemeral runs. */
export class InMemoryAuditLog implements AuditLog {
  private readonly log: AuditEntry[] = [];
  private readonly hmacKey?: string;

  constructor(options: { hmacKey?: string } = {}) {
    this.hmacKey = options.hmacKey;
  }

  async append(input: AuditInput): Promise<AuditEntry> {
    const prev = this.log[this.log.length - 1];
    const body: AuditEntryBody = {
      ...input,
      seq: this.log.length,
      prevHash: prev ? prev.hash : GENESIS_HASH,
      ts: input.ts ?? new Date().toISOString(),
    };
    const entry: AuditEntry = { ...body, hash: hashEntry(body, this.hmacKey) };
    this.log.push(entry);
    return entry;
  }

  async entries(): Promise<AuditEntry[]> {
    return [...this.log];
  }

  verify() {
    return verifyChain(this.log, this.hmacKey);
  }
}

/**
 * Append-only JSONL audit log backed by a file. Each line is one
 * {@link AuditEntry}. The previous hash is tracked in memory; on startup the
 * existing file (if any) is read once to seed the chain.
 */
export class HashChainAuditLog implements AuditLog {
  private readonly path: string;
  private readonly hmacKey?: string;
  private seq: number;
  private prevHash: string;

  constructor(options: { path: string; hmacKey?: string }) {
    this.path = options.path;
    this.hmacKey = options.hmacKey;
    mkdirSync(dirname(this.path), { recursive: true });
    const existing = this.readFile();
    this.seq = existing.length;
    this.prevHash = existing.length
      ? existing[existing.length - 1]!.hash
      : GENESIS_HASH;
  }

  private readFile(): AuditEntry[] {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return [];
    }
    return raw
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as AuditEntry);
  }

  async append(input: AuditInput): Promise<AuditEntry> {
    const body: AuditEntryBody = {
      ...input,
      seq: this.seq,
      prevHash: this.prevHash,
      ts: input.ts ?? new Date().toISOString(),
    };
    const entry: AuditEntry = { ...body, hash: hashEntry(body, this.hmacKey) };
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    this.seq += 1;
    this.prevHash = entry.hash;
    return entry;
  }

  async entries(): Promise<AuditEntry[]> {
    return this.readFile();
  }

  verify() {
    return verifyChain(this.readFile(), this.hmacKey);
  }
}
