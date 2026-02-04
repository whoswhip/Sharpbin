import type { PageServerLoad } from './$types';
import { env } from '$env/dynamic/private';
import { error, isHttpError } from '@sveltejs/kit';
import { extractError } from '$lib/utils/misc';

const API_URL = env.VITE_API_URL ?? 'http://localhost:5050';

export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch(`${API_URL}/api/stats`);

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
