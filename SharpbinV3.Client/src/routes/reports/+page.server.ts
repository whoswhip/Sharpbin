import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import {
	getServerToken,
	getUserFromToken,
	clearServerTokens,
	hasRole,
	roles
} from '$lib/utils/auth';
import type { ReportListResponse } from '$lib/types/report';
import { extractError } from '$lib/utils/misc';

function normalizeTarget(value: string | null): 'all' | 'pastes' | 'users' {
	if (value === 'pastes' || value === 'users') return value;
	return 'all';
}

export const load: PageServerLoad = async ({ fetch, cookies, url, request }) => {
	const token = getServerToken(cookies);
	if (!token) throw error(401, 'Login required');

	const user = getUserFromToken(token);
	if (!user) {
		clearServerTokens(cookies);
		throw error(401, 'Invalid token');
	}

	if (!hasRole(user.roles, roles.Admin) && !hasRole(user.roles, roles.Moderator)) {
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

	const headers = new Headers(request.headers);
	headers.set('Authorization', `Bearer ${token}`);

	const reportsRes = await fetch(`${apiUrl}/api/report/${target}?${query.toString()}`, {
		headers: headers
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
