import { proxyBackendRequest } from '$lib/server/proxy';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = ({ params, request, url }) => {
	return proxyBackendRequest('/openapi', params.path, request, url);
};
