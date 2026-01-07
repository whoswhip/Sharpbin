import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ fetch, url }) => {
	try {
		const res = await fetch('/api/auth/info');
		const options = await res.json();
		return { options, url: url.href };
	} catch {
		return { options: null, url: url.href };
	}
};
