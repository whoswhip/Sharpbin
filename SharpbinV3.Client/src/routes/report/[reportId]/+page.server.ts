import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import { getServerToken, clearServerTokens, roles, getUserFromToken } from '$lib/utils/auth';
import type { Report } from '$lib/types/report';

export const load: PageServerLoad = async ({ fetch, cookies, params, url, request }) => {
	const token = getServerToken(cookies);
	if (!token) throw error(401, 'Login required');

	const user = getUserFromToken(token);
	if (!user) {
		clearServerTokens(cookies);
		throw error(401, 'Invalid token');
	}
	const canEdit = (user.roles & roles.Admin) !== 0 || (user.roles & roles.Moderator) !== 0;
	const headers = new Headers(request.headers);
	headers.set('Authorization', `Bearer ${token}`);

	const res = await fetch(`${apiUrl}/api/report/${params.reportId}`, {
		headers: headers
	});

	if (!res.ok) {
		const { message } = await res.json().catch(() => ({}));
		throw error(res.status, message ?? 'Request failed');
	}

	const report = (await res.json()) as Report;
	const optionsRes = await fetch(`${apiUrl}/api/report/options`);
	const options = optionsRes.ok ? await optionsRes.json() : { types: [], statuses: [] };

	return { report, url: url.href, canEdit, options };
};
