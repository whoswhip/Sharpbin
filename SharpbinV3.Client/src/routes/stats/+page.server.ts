import type { PageServerLoad } from './$types';
import { apiUrl } from '$lib/server/api';
import { error, isHttpError } from '@sveltejs/kit';
import { extractError } from '$lib/utils/misc';

export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch(`${apiUrl}/api/stats`);

		if (!res.ok) {
			const json = await res.json().catch(() => ({}));
			const message = extractError(json);
			throw error(res.status, message ?? 'Failed to load statistics');
		}
		const stats = await res.json();
		return { stats };
	} catch (e) {
		if (isHttpError(e)) throw e;
		throw error(500, 'Failed to load statistics');
	}
};
