import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const CACHE_DIR = '.cache/og-images';
const CACHE_DB_PATH = join(CACHE_DIR, 'index.db');
const CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000;
const CACHE_CLEAN_INTERVAL_MS = 60 * 60 * 1000;
const CACHE_STALE_WHILE_REVALIDATE_SECONDS = 300;
const PURGE_BATCH_SIZE = 200;

type CacheRow = {
	relativePath: string;
	pasteExpiresAt: number | null;
	cacheExpiresAt: number;
};

type ExpiredCacheRow = {
	pasteId: string;
	relativePath: string;
};

export type CachedOgImage = {
	jpg: Buffer;
	ttlSeconds: number;
};

export type StoreCachedOgImageInput = {
	id: string;
	jpg: Buffer;
	pasteExpiresAt?: number | null;
};

let database: DatabaseSync | null = null;
let lastPurgeAt = 0;
let purgeInFlight: Promise<void> | null = null;

function getDatabase(): DatabaseSync {
	if (database) return database;

	mkdirSync(CACHE_DIR, { recursive: true });
	const nextDatabase = new DatabaseSync(CACHE_DB_PATH);
	nextDatabase.exec('PRAGMA journal_mode = WAL');
	nextDatabase.exec('PRAGMA synchronous = NORMAL');
	nextDatabase.exec(`
		CREATE TABLE IF NOT EXISTS og_image_cache (
			paste_id TEXT PRIMARY KEY,
			relative_path TEXT NOT NULL,
			paste_expires_at INTEGER,
			cache_expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_og_image_cache_cache_expires_at
		ON og_image_cache (cache_expires_at);
		CREATE INDEX IF NOT EXISTS idx_og_image_cache_paste_expires_at
		ON og_image_cache (paste_expires_at);
	`);
	database = nextDatabase;
	return nextDatabase;
}

function getCacheTtlExpiry(pasteExpiresAt?: number | null): number {
	const cacheExpiresAt = Date.now() + CACHE_EXPIRY_MS;
	if (!pasteExpiresAt) return cacheExpiresAt;
	return Math.min(cacheExpiresAt, pasteExpiresAt);
}

export function getCacheTtlSeconds(expiresAt?: number | null): number {
	if (!expiresAt) return CACHE_EXPIRY_MS / 1000;
	const secondsUntilExpiry = Math.floor((expiresAt - Date.now()) / 1000);
	if (secondsUntilExpiry <= 0) return 0;
	return Math.min(secondsUntilExpiry, CACHE_EXPIRY_MS / 1000);
}

export function getCacheControlHeader(ttlSeconds: number): string {
	return ttlSeconds > 0
		? `private, max-age=${ttlSeconds}, stale-while-revalidate=${CACHE_STALE_WHILE_REVALIDATE_SECONDS}`
		: 'no-store, max-age=0';
}

function getShardRelativePath(id: string): string {
	const hash = createHash('sha256').update(id).digest('hex');
	return join(hash.slice(0, 2), hash.slice(2, 4), `${id}.jpg`);
}

function getAbsolutePath(relativePath: string): string {
	return join(CACHE_DIR, relativePath);
}

async function deleteCacheFile(relativePath: string): Promise<void> {
	await unlink(getAbsolutePath(relativePath)).catch(() => undefined);
}

async function deleteCacheEntry(id: string, relativePath?: string): Promise<void> {
	const db = getDatabase();
	const resolvedPath =
		relativePath ??
		((db
			.prepare('SELECT relative_path AS relativePath FROM og_image_cache WHERE paste_id = ?')
			.get(id) as { relativePath: string } | undefined)?.relativePath ?? null);

		db.prepare('DELETE FROM og_image_cache WHERE paste_id = ?').run(id);
	if (resolvedPath) {
		await deleteCacheFile(resolvedPath);
	}
}

export async function getCachedOgImage(id: string): Promise<CachedOgImage | null> {
	const db = getDatabase();
	const row = db
		.prepare(
			'SELECT relative_path AS relativePath, paste_expires_at AS pasteExpiresAt, cache_expires_at AS cacheExpiresAt FROM og_image_cache WHERE paste_id = ?'
		)
		.get(id) as CacheRow | undefined;

	if (!row) {
		return null;
	}

	const ttlSeconds = getCacheTtlSeconds(row.cacheExpiresAt);
	if (ttlSeconds <= 0) {
		await deleteCacheEntry(id, row.relativePath);
		return null;
	}

	if (typeof row.pasteExpiresAt === 'number' && row.pasteExpiresAt <= Date.now()) {
		await deleteCacheEntry(id, row.relativePath);
		return null;
	}

	try {
		const jpg = await readFile(getAbsolutePath(row.relativePath));
		return { jpg, ttlSeconds };
	} catch {
		await deleteCacheEntry(id, row.relativePath);
		return null;
	}
}

export async function storeCachedOgImage({
	id,
	jpg,
	pasteExpiresAt
}: StoreCachedOgImageInput): Promise<void> {
	const db = getDatabase();
	const relativePath = getShardRelativePath(id);
	const absolutePath = getAbsolutePath(relativePath);
	const tempPath = `${absolutePath}.tmp-${process.pid}-${Date.now()}`;
	await mkdir(dirname(absolutePath), { recursive: true });
	await writeFile(tempPath, jpg);
	await rename(tempPath, absolutePath);

	try {
		db.prepare(
			`INSERT INTO og_image_cache (paste_id, relative_path, paste_expires_at, cache_expires_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(paste_id) DO UPDATE SET
				relative_path = excluded.relative_path,
				paste_expires_at = excluded.paste_expires_at,
				cache_expires_at = excluded.cache_expires_at`
		).run(id, relativePath, pasteExpiresAt ?? null, getCacheTtlExpiry(pasteExpiresAt));
	} catch (error) {
		await unlink(absolutePath).catch(() => undefined);
		throw error;
	}
}

async function purgeExpiredCache(limit: number = PURGE_BATCH_SIZE): Promise<void> {
	const db = getDatabase();
	const now = Date.now();
	const rows = db
		.prepare(
			`SELECT paste_id AS pasteId, relative_path AS relativePath
			 FROM og_image_cache
			 WHERE cache_expires_at <= ?
				OR (paste_expires_at IS NOT NULL AND paste_expires_at <= ?)
			 LIMIT ?`
		)
		.all(now, now, limit) as ExpiredCacheRow[];

	if (rows.length === 0) {
		return;
	}

	for (const row of rows) {
		await deleteCacheFile(row.relativePath);
		db.prepare('DELETE FROM og_image_cache WHERE paste_id = ?').run(row.pasteId);
	}
}

export function scheduleOgImageCachePurge(): void {
	const now = Date.now();
	if (purgeInFlight || now - lastPurgeAt < CACHE_CLEAN_INTERVAL_MS) {
		return;
	}

	purgeInFlight = purgeExpiredCache().finally(() => {
		lastPurgeAt = Date.now();
		purgeInFlight = null;
	});
}