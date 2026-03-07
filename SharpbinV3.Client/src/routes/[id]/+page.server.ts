import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';
import { getServerToken } from '$lib/utils/auth';
import { apiUrl, viewInternalApiKey } from '$lib/server/api';
import { error } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ params, fetch, url, cookies, parent }) => {
	const { id } = params;
	const parentData = await parent().catch(() => null);

	const token = getServerToken(cookies);

	const pasteRes = await fetch(`${apiUrl}/api/paste/${id}`, {
		headers: {
			Authorization: token ? `Bearer ${token}` : ''
		}
	});

	if (pasteRes.status === 404) {
		throw error(pasteRes.status, 'Paste not found.');
	}

	const viewed = await fetch(`${apiUrl}/api/paste/${id}/view`, {
		method: 'POST',
		headers: {
			'X-Internal-API-Key': viewInternalApiKey,
			Authorization: token ? `Bearer ${token}` : ''
		}
	});

	const pasteData = await pasteRes.json();
	const paste = pasteData.paste as Paste;

	if (viewed.status === 200) {
		const viewJson = await viewed.json();
		if (viewJson.success === true && viewJson.message !== 'View already recorded.') {
			pasteData.views += 1;
		}
	} else {
		console.error(
			`Failed to increment view count for paste ${id}, status code ${viewed.status}: ${await viewed.text()}`
		);
		if (viewInternalApiKey === '') {
			console.error(
				'The API key for internal requests is not set. Please configure it in the environment variables.'
			);
		}
	}

	const pasteContent = await fetch(`/api/paste/${id}/raw`);
	const pasteOptions = await fetch('/api/paste/info');
	const options = await pasteOptions.json();
	const content = await pasteContent.text();

	return {
		paste,
		content,
		options,
		authOptions:
			parentData && typeof parentData === 'object' && parentData !== null && 'options' in parentData
				? (parentData as { options?: unknown }).options
				: null,
		url: url.href
	};
};
