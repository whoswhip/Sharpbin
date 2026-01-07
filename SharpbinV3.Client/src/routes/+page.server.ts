import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, url }) => {
	try {
		const res = await fetch('/api/paste/create/options');
		const options = await res.json();
		return { options, url: url.href };
	} catch {
		return { options: null, url: url.href };
	}
};
