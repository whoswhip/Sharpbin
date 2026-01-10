import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';
import { getServerToken } from '$lib/utils/auth';
import { env } from '$env/dynamic/private';

export const load: PageServerLoad = async ({ params, fetch, url, cookies }) => {
	const { id } = params;

	const paste = await fetch(`/api/paste/${id}`);
	if (paste.status === 404) {
		return {
			status: 404,
			error: { message: 'Paste not found' }
		};
	}

	const token = getServerToken(cookies);

	const viewed = await fetch(`/api/paste/${id}/view`, {
		method: 'POST',
		headers: {
			'X-Internal-API-Key': env.VIEW_INTERNAL_API_KEY ?? env.View_HMAC_Internal_API_Key ?? '',
			Authorization: token ? `Bearer ${token}` : ''
		}
	});

	const pasteData = (await paste.json()) as Paste;
	if (viewed.status === 200) {
		const viewJson = await viewed.json();
		if (viewJson.success === true && viewJson.message !== 'View already recorded.') {
			pasteData.views += 1;
		}
	}
	else {
		console.error(`Failed to increment view count for paste ${id}: ${await viewed.text()}`);
	}

	const pasteContent = await fetch(`/api/paste/${id}/raw`);
	const pasteOptions = await fetch('/api/paste/info');	
	const options = await pasteOptions.json();
	const content = await pasteContent.text();

	return { paste: pasteData, content, options, url: url.href };
};
