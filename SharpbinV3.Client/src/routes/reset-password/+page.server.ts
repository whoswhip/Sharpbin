import { apiUrl } from '$lib/server/api';
import { extractError } from '$lib/utils/misc';
import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, request }) => {
	const token = url.searchParams.get('token');
	if (!token) {
		throw error(400, 'Reset token is required.');
	}

	const headers = new Headers(request.headers);
	const res = await fetch(`${apiUrl}/api/auth/password/reset-info?token=${token}`, { headers });
	const json = await res.json().catch(() => null);
	if (!res.ok) {
		const message = extractError(json);
		throw error(res.status, message ?? 'Request failed');
	}

	return {
		token,
		username: typeof json?.username === 'string' ? json.username : undefined,
		requiresTotp: Boolean(json?.requiresTotp)
	};
};
