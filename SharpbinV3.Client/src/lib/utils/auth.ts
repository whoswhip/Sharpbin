import { browser } from '$app/environment';

const TOKEN_KEY = 'token';
const REFRESH_TOKEN_KEY = 'refreshToken';

export function getToken() {
	if (!browser) return null;
	return localStorage.getItem(TOKEN_KEY);
}

export function getRefreshToken() {
	if (!browser) return null;
	return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(token: string, refreshToken: string) {
	if (!browser) return;
	localStorage.setItem(TOKEN_KEY, token);
	localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens() {
	if (!browser) return;
	localStorage.removeItem(TOKEN_KEY);
	localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export async function refreshTokenIfNeeded() {
	const token = getToken();
	const refreshToken = getRefreshToken();
	if (!token || !refreshToken) return;
	const payload = JSON.parse(atob(token.split('.')[1]));
	const exp = payload.exp * 1000;
	const now = Date.now();
	if (exp - now < 2 * 60 * 1000) {
		const res = await fetch('/api/auth/refresh', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token, refreshToken })
		});
		if (res.ok) {
			const data = await res.json();
			if (data.token.token && data.token.refreshToken) {
				setTokens(data.token.token, data.token.refreshToken);
			}
		}
	}
}

export function startTokenRefreshInterval() {
	if (!browser) return;
	setInterval(refreshTokenIfNeeded, 60 * 1000);
}
