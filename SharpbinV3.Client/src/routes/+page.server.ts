import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch }) => {
	const res = await fetch('/api/paste/create/options');
	const options = await res.json();
	return { options };
};
