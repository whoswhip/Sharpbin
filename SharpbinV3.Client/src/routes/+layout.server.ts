import type { LayoutServerLoad } from './$types';
import { error } from '@sveltejs/kit';

export const load: LayoutServerLoad = async ({ fetch, url }) => {
	const res = await fetch('/api/auth/info');
	const pasteOptionsRes = await fetch('/api/paste/info');

	if (!res.ok || !pasteOptionsRes.ok) {
		throw error(503, 'Failed to load site configuration.');
	}

	const options = await res.json();
	const pasteOptions = await pasteOptionsRes.json();
	return { options, pasteOptions, url: url.href };
};
