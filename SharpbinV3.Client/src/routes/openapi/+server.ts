import { proxyBackendRequest } from '$lib/server/proxy';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = ({ request, url }) => {
	return proxyBackendRequest('/openapi', '', request, url);
};
