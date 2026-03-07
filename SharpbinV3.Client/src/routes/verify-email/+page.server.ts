import { apiUrl } from '$lib/server/api';
import { extractError } from '$lib/utils/misc';
import { error } from '@sveltejs/kit';

export const load = async ({ url }) => {
	const token = url.searchParams.get('token');
	if (token) {
		const res = await fetch(`${apiUrl}/api/auth/verify-email?token=${token}`);
		if (!res.ok) {
			const json = await res.json().catch();
			const message = extractError(json);
			throw error(res.status, message ?? 'Request failed');
		}
	}
};
