import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ fetch }) => {
	try {
		const res = await fetch('/api/auth/info');
		const options = await res.json();
		return { options };
	} catch {
		return { options: null };
	}
};
