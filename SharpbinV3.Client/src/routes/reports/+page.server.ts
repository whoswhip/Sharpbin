import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import { getServerToken } from '$lib/utils/auth';
import type { ReportListResponse } from '$lib/types/report';
import { extractError } from '$lib/utils/misc';

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

function normalizeTarget(value: string | null): 'all' | 'pastes' | 'users' {
	if (value === 'pastes' || value === 'users') return value;
	return 'all';
}

export const load: PageServerLoad = async ({ fetch, cookies, url }) => {
	const token = getServerToken(cookies);
	if (!token) throw error(401, 'Login required');

	const roles = decodeJwtRoles(token);
	if ((roles & 2) === 0 && (roles & 4) === 0) {
		throw error(403, 'You do not have permission to view reports.');
	}

	const target = normalizeTarget(url.searchParams.get('target'));
	const status = url.searchParams.get('status') ?? '';
	const type = url.searchParams.get('type') ?? '';
	const pasteId = url.searchParams.get('pasteId') ?? '';
	const userUuid = url.searchParams.get('userUuid') ?? '';
	const pageParam = Number(url.searchParams.get('page') ?? '1');
	const page = Number.isFinite(pageParam) ? Math.max(1, pageParam) : 1;

	const query = new URLSearchParams({ page: String(page), pageSize: '20' });
	if (status) query.set('status', status);
	if (type) query.set('type', type);
	if ((target === 'pastes' || target === 'all') && pasteId) query.set('pasteId', pasteId);
	if ((target === 'users' || target === 'all') && userUuid) query.set('userUUID', userUuid);

	const reportsRes = await fetch(`${apiUrl}/api/report/${target}?${query.toString()}`, {
		headers: { Authorization: `Bearer ${token}` }
	});

	if (!reportsRes.ok) {
		const json = await reportsRes.json().catch(() => ({}));
		throw error(reportsRes.status, extractError(json) ?? 'Request failed');
	}

	const reports = (await reportsRes.json()) as ReportListResponse;

	const optionsRes = await fetch(`${apiUrl}/api/report/options`);
	const options = optionsRes.ok ? await optionsRes.json() : { types: [], statuses: [] };

	return {
		reports,
		options,
		filters: { target, status, type, pasteId, userUuid, page }
	};
};
