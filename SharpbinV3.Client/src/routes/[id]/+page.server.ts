import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';
import { getServerToken } from '$lib/utils/auth';
import { apiUrl, viewInternalApiKey } from '$lib/server/api';
import { error } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ params, fetch, url, cookies, parent, request }) => {
	const { id } = params;
	if (!id) {
		// realistically this shouldnt happen
		throw error(400, 'Missing paste id.');
	}
	const parentData = await parent().catch(() => null);
	const token = getServerToken(cookies);
	const userAgent = request.headers.get('user-agent') ?? 'Sharpbin Client';
	const clientHeaders = new Headers(request.headers);
	clientHeaders.set('Authorization', token ? `Bearer ${token}` : '');
	clientHeaders.set('User-Agent', userAgent);

	const pasteRes = await fetch(`${apiUrl}/api/paste/${id}`, { headers: clientHeaders });

	if (pasteRes.status === 404) {
		throw error(pasteRes.status, 'Paste not found.');
	}

	const viewedHeaders = new Headers(clientHeaders);
	viewedHeaders.set('X-Internal-API-Key', viewInternalApiKey);
	const viewed = await fetch(`${apiUrl}/api/paste/${id}/view`, {
		method: 'POST',
		headers: viewedHeaders
	});

	const pasteData = await pasteRes.json();
	const paste = pasteData.paste as Paste;

	if (viewed.status === 200) {
		const viewJson = await viewed.json();
		if (viewJson.success === true && viewJson.message === 'Paste view recorded.') {
			pasteData.views += 1;
		}
	} else if (viewInternalApiKey === '') {
		console.error(
			'The API key for internal requests is not set. Please configure it in the environment variables.'
		);
	}

	const pasteContent = await fetch(`${apiUrl}/api/paste/${id}/raw`, { headers: clientHeaders });
	const pasteOptions = await fetch(`${apiUrl}/api/paste/info`, { headers: clientHeaders });
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
