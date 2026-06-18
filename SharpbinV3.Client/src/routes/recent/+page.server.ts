import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';
import { extractError } from '$lib/utils/misc';
import { error } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ fetch, request }) => {
	const headers = new Headers(request.headers);
	const res = await fetch('/api/paste/recent', { headers });
	if (!res.ok) {
		const errorMsg = extractError(await res.json()) || 'Failed to fetch recent pastes.';
		throw error(res.status, errorMsg);
	}
	const recentPastes: Paste[] = await res.json();
	return { recentPastes };
};
