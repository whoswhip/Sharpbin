import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch('/api/paste/create/options');
		const options = await res.json();
		return { options };
	} catch {
		return { options: null };
	}
};
