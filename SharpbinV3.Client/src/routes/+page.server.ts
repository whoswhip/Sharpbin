import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ fetch, url }) => {
	try {
		const optionsRes = await fetch('/api/paste/info');
		const authInfo = await fetch('/api/auth/info');
		const options = await optionsRes.json();
		const auth = await authInfo.json();
		return { options, auth, url: url.href };
	} catch {
		return { options: null, url: url.href };
	}
};
