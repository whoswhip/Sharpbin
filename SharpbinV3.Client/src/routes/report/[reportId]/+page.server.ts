import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import { getServerToken } from '$lib/utils/auth';
import type { Report } from '$lib/types/report';

const API_URL = env.VITE_API_URL ?? 'http://localhost:5050';

function decodeJwtRoles(token?: string | null): number[] {
	try {
		if (!token) return [];
		const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
		const roles = payload?.role;
		if (Array.isArray(roles)) {
			return roles.map((r: string) => parseInt(r, 10)).filter((r: number) => !isNaN(r));
		}
		return [];
	} catch {
		return [];
	}
}

export const load: PageServerLoad = async ({ fetch, cookies, params, url }) => {
	const token = getServerToken(cookies);
	if (!token) throw error(401, 'Login required');
	const roles = decodeJwtRoles(token);
	const canEdit = roles.includes(1) || roles.includes(255);

	const res = await fetch(`${API_URL}/api/report/${params.reportId}`, {
		headers: { Authorization: `Bearer ${token}` }
	});

	if (!res.ok) {
		const { message } = await res.json().catch(() => ({}));
		throw error(res.status, message ?? 'Request failed');
	}

	const report = (await res.json()) as Report;
	const optionsRes = await fetch(`${API_URL}/api/report/options`);
	const options = optionsRes.ok ? await optionsRes.json() : { types: [], statuses: [] };

	return { report, url: url.href, canEdit, options };
};
