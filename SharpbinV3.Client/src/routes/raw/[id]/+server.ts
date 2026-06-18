import type { RequestHandler } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';

export const GET: RequestHandler = async ({ params, request }) => {
	const { id } = params;
	const headers = new Headers(request.headers);

	const res = await fetch(`${apiUrl}/api/paste/${id}/raw`, {
		headers: headers
	});

	if (res.status === 404) {
		return new Response(null, {
			status: 404,
			statusText: 'Not Found'
		});
	}
	const responseHeaders = new Headers(res.headers);
	responseHeaders.delete('content-encoding');
	responseHeaders.delete('content-length');
	responseHeaders.delete('transfer-encoding');

	return new Response(await res.arrayBuffer(), {
		status: res.status,
		statusText: res.statusText,
		headers: responseHeaders
	});
};
