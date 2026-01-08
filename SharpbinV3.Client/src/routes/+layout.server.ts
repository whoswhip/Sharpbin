import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ fetch, url }) => {
	try {
		const res = await fetch('/api/auth/info');
		const pasteOptionsRes = await fetch('/api/paste/info');
		const options = await res.json();
		const pasteOptions = await pasteOptionsRes.json();
		return { options, pasteOptions, url: url.href };
	} catch {
		return { options: null, pasteOptions: null, url: url.href };
	}
};
