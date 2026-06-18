import { apiUrl } from '$lib/server/api';

const methodsWithoutBody = new Set(['GET', 'HEAD']);

export async function proxyBackendRequest(
	prefix: string,
	path: string,
	request: Request,
	url: URL
) {
	const targetUrl = new URL(`${prefix}/${path}`.replace(/\/+$/, ''), apiUrl);
	targetUrl.search = url.search;

	const headers = new Headers(request.headers);
	headers.delete('host');

	const init: RequestInit = {
		method: request.method,
		headers,
		redirect: 'manual'
	};

	if (!methodsWithoutBody.has(request.method)) {
		init.body = await request.arrayBuffer();
	}

	return fetch(targetUrl, init);
}
