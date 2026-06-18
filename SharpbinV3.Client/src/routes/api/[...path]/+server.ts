import { proxyBackendRequest } from '$lib/server/proxy';
import type { RequestHandler } from './$types';

const handle: RequestHandler = ({ params, request, url }) => {
	return proxyBackendRequest('/api', params.path, request, url);
};

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const OPTIONS = handle;
