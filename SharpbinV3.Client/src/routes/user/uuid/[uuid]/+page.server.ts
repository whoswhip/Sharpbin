import type { RequestEvent } from '@sveltejs/kit';
import { error, redirect } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import { getServerToken } from '$lib/utils/auth';

export const load = async ({ params, fetch, cookies }: RequestEvent) => {
	const token = getServerToken(cookies);
	const uuid = (params as Record<string, string | undefined>).uuid;

	if (!uuid) throw error(404, 'User not found');

	const res = await fetch(`${apiUrl}/api/user/uuid/${uuid}`, {
		headers: token ? { Authorization: `Bearer ${token}` } : undefined
	});

	if (!res.ok) {
		const { message } = await res.json().catch(() => ({}));
		throw error(res.status, message ?? 'Request failed');
	}

	const { user } = (await res.json()) as { user: { username: string } };
	throw redirect(302, `/user/${encodeURIComponent(user.username)}`);
};
