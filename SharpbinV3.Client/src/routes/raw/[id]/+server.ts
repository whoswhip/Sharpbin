import type { RequestHandler } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';

export const GET: RequestHandler = async ({ params }) => {
	const { id } = params;

	const res = await fetch(`${apiUrl}/api/paste/${id}/raw`);

	if (res.status === 404) {
		return new Response(null, {
			status: 404,
			statusText: 'Not Found'
		});
	}
	const content = await res.text();
	return new Response(content, {
		headers: {
			'Content-Type': 'text/plain; charset=utf-8'
		}
	});
};
