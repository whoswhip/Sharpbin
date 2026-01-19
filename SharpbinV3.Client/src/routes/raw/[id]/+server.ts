import type { RequestHandler } from '@sveltejs/kit';

const apiUrl = process.env.VITE_API_URL || 'http://localhost:5050';

export const GET: RequestHandler = async ({ params }) => {
	const { id } = params;

	const res = await fetch(`${apiUrl}/api/paste/${id}/raw`);

	if (res.status === 404) {
		return new Response('Paste not found', { status: 404 });
	}
	const content = await res.text();
	return new Response(content, {
		headers: {
			'Content-Type': 'text/plain; charset=utf-8'
		}
	});
};
