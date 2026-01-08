import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';

export const load: PageServerLoad = async ({ params, fetch, url }) => {
	const { id } = params;

	const paste = await fetch(`/api/paste/${id}`);
	if (paste.status === 404) {
		return {
			status: 404,
			error: { message: 'Paste not found' }
		};
	}
	const pasteData = (await paste.json()) as Paste;
	const pasteContent = await fetch(`/api/paste/${id}/raw`);
	const pasteOptions = await fetch('/api/paste/info');
	const options = await pasteOptions.json();
	const content = await pasteContent.text();

	return { paste: pasteData, content, options, url: url.href };
};
