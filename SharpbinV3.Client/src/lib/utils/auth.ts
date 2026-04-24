import { browser } from '$app/environment';
import type { Cookies } from '@sveltejs/kit';
import { user } from '$lib/stores/user';
import type { JWTUser } from '$lib/types/user';

export const roles = {
	User: 1,
	Moderator: 2,
	Admin: 4
} as const;

export type Role = keyof typeof roles;

const TOKEN_KEY = 'token';
const REFRESH_TOKEN_KEY = 'refreshToken';
const TOKEN_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 180;
const AUTH_TOKENS_UPDATED_EVENT = 'auth:tokens-updated';
const AUTH_TOKENS_CLEARED_EVENT = 'auth:tokens-cleared';

let refreshPromise: Promise<void> | null = null;
let lastRefreshAttempt = 0;
let refreshFailureCount = 0;
let refreshIntervalId: ReturnType<typeof setInterval> | null = null;
let listenersRegistered = false;

function getCookieValue(key: string) {
	if (!browser) return null;
	const entry = document.cookie
		.split('; ')
		.find((cookieEntry) => cookieEntry.startsWith(`${key}=`));
	if (!entry) return null;
	const value = entry.slice(key.length + 1);
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function getCookieSecurityAttributes() {
	if (!browser) return '';
	return window.location.protocol === 'https:' ? '; secure' : '';
}

function emitAuthEvent(eventName: string) {
	if (!browser) return;
	window.dispatchEvent(new CustomEvent(eventName));
}

function decodeBase64Url(value: string) {
	const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
	const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
	return atob(normalized + padding);
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
	try {
		const [, payload] = token.split('.');
		if (!payload) return null;
		return JSON.parse(decodeBase64Url(payload));
	} catch {
		return null;
	}
}

function parseBooleanClaim(value: unknown) {
	if (typeof value === 'string') return value.toLowerCase() === 'true';
	return Boolean(value);
}

function parseNumberClaim(value: unknown): number | null {
	const numeric =
		typeof value === 'number' ? value : typeof value === 'string' ? parseInt(value, 10) : NaN;
	return Number.isFinite(numeric) ? numeric : null;
}

function isPermanentRefreshFailure(status: number, message?: string) {
	if (status === 401 || status === 403) return true;
	if (!message) return false;
	const normalized = message.toLowerCase();
	return (
		normalized.includes('invalid') ||
		normalized.includes('expired') ||
		normalized.includes('revoked') ||
		normalized.includes('malformed')
	);
}

async function queueRefresh(token: string, refreshToken: string) {
	if (refreshPromise) {
		await refreshPromise;
		return;
	}

	const now = Date.now();
	const timeSinceLastAttempt = now - lastRefreshAttempt;
	const minDelay = getBackoffDelay(refreshFailureCount);
	if (timeSinceLastAttempt < minDelay) return;

	refreshPromise = performRefresh(token, refreshToken);
	try {
		await refreshPromise;
	} finally {
		refreshPromise = null;
	}
}

export function getToken() {
	return getCookieValue(TOKEN_KEY);
}

export function getRefreshToken() {
	return getCookieValue(REFRESH_TOKEN_KEY);
}

export function setTokens(token: string, refreshToken: string) {
	if (!browser) return;
	const secureAttributes = getCookieSecurityAttributes();
	document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${TOKEN_COOKIE_MAX_AGE_SECONDS}; samesite=strict${secureAttributes}`;
	document.cookie = `${REFRESH_TOKEN_KEY}=${encodeURIComponent(refreshToken)}; path=/; max-age=${TOKEN_COOKIE_MAX_AGE_SECONDS}; samesite=strict${secureAttributes}`;
	refreshFailureCount = 0;
	emitAuthEvent(AUTH_TOKENS_UPDATED_EVENT);
}

export function clearTokens() {
	if (!browser) return;
	const secureAttributes = getCookieSecurityAttributes();
	document.cookie = `${TOKEN_KEY}=; path=/; max-age=0; samesite=strict${secureAttributes}`;
	document.cookie = `${REFRESH_TOKEN_KEY}=; path=/; max-age=0; samesite=strict${secureAttributes}`;
	user.set(null);
	emitAuthEvent(AUTH_TOKENS_CLEARED_EVENT);
}

function getBackoffDelay(attempt: number): number {
	const baseDelay = 1000;
	const maxDelay = 30000;
	const delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
	return delay + Math.random() * 1000;
}

export async function refreshTokenIfNeeded() {
	const token = getToken();
	const refreshToken = getRefreshToken();
	if (!token || !refreshToken) return;

	const payload = decodeJwtPayload(token);
	const expClaim = payload ? parseNumberClaim(payload.exp) : null;
	if (expClaim === null) {
		await queueRefresh(token, refreshToken);
		return;
	}

	const exp = expClaim * 1000;
	const now = Date.now();

	if (exp - now >= 2 * 60 * 1000) return;
	await queueRefresh(token, refreshToken);
}

async function performRefresh(token: string, refreshToken: string) {
	lastRefreshAttempt = Date.now();

	try {
		const res = await fetch('/api/auth/refresh', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token, refreshToken })
		});
		let data: {
			success?: boolean;
			message?: string;
			token?: { token?: string; refreshToken?: string };
		} | null = null;
		try {
			data = await res.json();
		} catch {
			data = null;
		}

		if (!res.ok) {
			refreshFailureCount++;
			if (isPermanentRefreshFailure(res.status, data?.message)) {
				clearTokens();
			}
			return;
		}

		if (data?.success && data.token?.token && data.token?.refreshToken) {
			setTokens(data.token.token, data.token.refreshToken);
		} else {
			refreshFailureCount++;
			if (isPermanentRefreshFailure(res.status, data?.message)) {
				clearTokens();
			}
		}
	} catch {
		refreshFailureCount++;
	}
}

export function startTokenRefreshInterval() {
	if (!browser) return;
	if (refreshIntervalId !== null) return;
	refreshIntervalId = setInterval(() => {
		void refreshTokenIfNeeded();
	}, 60 * 1000);

	if (!listenersRegistered) {
		window.addEventListener('focus', () => {
			void refreshTokenIfNeeded();
		});
		document.addEventListener('visibilitychange', () => {
			if (document.visibilityState === 'visible') {
				void refreshTokenIfNeeded();
			}
		});
		window.addEventListener('online', () => {
			void refreshTokenIfNeeded();
		});
		listenersRegistered = true;
	}

	void refreshTokenIfNeeded();
}

export function getServerToken(cookies: Cookies) {
	return cookies.get('token');
}

export function getServerRefreshToken(cookies: Cookies) {
	return cookies.get('refreshToken');
}

export function setServerTokens(cookies: Cookies, token: string, refreshToken: string) {
	cookies.set('token', token, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure: true,
		maxAge: TOKEN_COOKIE_MAX_AGE_SECONDS
	});
	cookies.set('refreshToken', refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure: true,
		maxAge: TOKEN_COOKIE_MAX_AGE_SECONDS
	});
}

export function clearServerTokens(cookies: Cookies) {
	cookies.delete('token', { path: '/' });
	cookies.delete('refreshToken', { path: '/' });
}

export function getUserFromToken(token: string): JWTUser | null {
	const payload = decodeJwtPayload(token);
	if (!payload) return null;

	const uuid = typeof payload.uuid === 'string' ? payload.uuid : null;
	const username = typeof payload.username === 'string' ? payload.username : null;
	const displayname = typeof payload.displayname === 'string' ? payload.displayname : '';
	const rolesClaim = parseNumberClaim(payload.roles);

	if (!uuid || !username || rolesClaim === null) return null;

	return {
		uuid,
		username,
		displayname,
		totpEnabled: parseBooleanClaim(payload.totp_enabled),
		roles: rolesClaim,
		isBanned: parseBooleanClaim(payload.is_banned)
	};
}

export const hasRole = (userRoles: number, role: number) => (userRoles & role) !== 0;

export const getUserRoles = (userRoles: number): Role[] =>
	(Object.keys(roles) as Role[]).filter((role) => hasRole(userRoles, roles[role]));
