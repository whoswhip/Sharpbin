import { browser } from '$app/environment';
import type { Cookies } from '@sveltejs/kit';
import { user } from '$lib/stores/user';

const TOKEN_KEY = 'token';
const REFRESH_TOKEN_KEY = 'refreshToken';

export function getToken() {
	if (!browser) return null;
	return (
		document.cookie
			.split('; ')
			.find((c) => c.startsWith(`${TOKEN_KEY}=`))
			?.split('=')[1] || null
	);
}

export function getRefreshToken() {
	if (!browser) return null;
	return (
		document.cookie
			.split('; ')
			.find((c) => c.startsWith(`${REFRESH_TOKEN_KEY}=`))
			?.split('=')[1] || null
	);
}

export function setTokens(token: string, refreshToken: string) {
	if (!browser) return;
	console.log('Setting tokens');
	document.cookie = `${TOKEN_KEY}=${token}; path=/; secure; samesite=strict`;
	document.cookie = `${REFRESH_TOKEN_KEY}=${refreshToken}; path=/; secure; samesite=strict`;
}

export function clearTokens() {
	if (!browser) return;
	console.log('Clearing tokens');
	document.cookie = `${TOKEN_KEY}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
	document.cookie = `${REFRESH_TOKEN_KEY}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
	user.set(null);
}

export async function refreshTokenIfNeeded() {
	const token = getToken();
	const refreshToken = getRefreshToken();
	if (!token || !refreshToken) return;

	const payload = JSON.parse(atob(token.split('.')[1]));
	const exp = payload.exp * 1000;
	const now = Date.now();

	if (exp - now < 2 * 60 * 1000) {
		console.log('Refreshing token...');
		const res = await fetch('/api/auth/refresh', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token, refreshToken })
		});
		if (res.ok) {
			const data = await res.json();
			if (data.success && data.token?.token && data.token?.refreshToken) {
				console.log('Token refreshed successfully');
				setTokens(data.token.token, data.token.refreshToken);
			} else {
				console.log('Invalid tokens received during refresh');
				clearTokens();
			}
		} else {
			console.log('Failed to refresh token');
			clearTokens();
		}
	}
	console.log('Token is still valid, no refresh needed');
}

export function startTokenRefreshInterval() {
	if (!browser) return;
	setInterval(refreshTokenIfNeeded, 60 * 1000);
}

export function getServerToken(cookies: Cookies) {
	return cookies.get('token');
}

export function getServerRefreshToken(cookies: Cookies) {
	return cookies.get('refreshToken');
}

export function setServerTokens(cookies: Cookies, token: string, refreshToken: string) {
	cookies.set('token', token, { path: '/', httpOnly: true, sameSite: 'strict', secure: true });
	cookies.set('refreshToken', refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure: true
	});
}

export function clearServerTokens(cookies: Cookies) {
	cookies.delete('token', { path: '/' });
	cookies.delete('refreshToken', { path: '/' });
}
