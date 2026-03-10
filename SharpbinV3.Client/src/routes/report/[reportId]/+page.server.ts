import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import { getServerToken } from '$lib/utils/auth';
import type { Report } from '$lib/types/report';

function decodeJwtRoles(token?: string | null): number {
	try {
		if (!token) return 0;
		const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
		const roles = payload?.role;
		if (typeof roles === 'number') return roles;
		if (typeof roles === 'string') {
			const parsed = parseInt(roles, 10);
			return isNaN(parsed) ? 0 : parsed;
		}
		return 0;
	} catch {
		return 0;
	}
}

export const load: PageServerLoad = async ({ fetch, cookies, params, url }) => {
	const token = getServerToken(cookies);
	if (!token) throw error(401, 'Login required');
	const roles = decodeJwtRoles(token);
	const canEdit = (roles & 2) !== 0 || (roles & 4) !== 0;

	const res = await fetch(`${apiUrl}/api/report/${params.reportId}`, {
		headers: { Authorization: `Bearer ${token}` }
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
