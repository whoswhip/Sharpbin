import type { PageServerLoad } from './$types';
import { error } from '@sveltejs/kit';
import { apiUrl } from '$lib/server/api';
import { getServerToken } from '$lib/utils/auth';
import type { User } from '$lib/types/user';
import type { Paste } from '$lib/types/paste';
import type { Pagination } from '$lib/types/pagination';
import type { Report, ReportListResponse } from '$lib/types/report';

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

function decodeJwtUuid(token?: string | null): string | null {
	try {
		if (!token) return null;
		const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
		const uuid = payload?.uuid;
		return typeof uuid === 'string' ? uuid : null;
	} catch {
		return null;
	}
}

export const load: PageServerLoad = async ({ params, fetch, cookies, url, parent }) => {
	const token = getServerToken(cookies);
	const { username } = params;
	const { options } = await parent();
	const jwtUuid = decodeJwtUuid(token);

	const res = await fetch(`${apiUrl}/api/user/${username}`, {
		headers: token ? { Authorization: `Bearer ${token}` } : undefined
	});

	if (!res.ok) {
		const { message } = await res.json().catch(() => ({}));
		throw error(res.status, message ?? 'Request failed');
	}

	const { user, pastes, pagination, reports, reportsPagination } = (await res.json()) as {
		user: User;
		pastes: Paste[];
		pagination: Pagination;
		reports?: Report[];
		reportsPagination?: Pagination;
	};

	const isOwner = jwtUuid ? user.uuid === jwtUuid : false;
	let reportsTarget: ReportListResponse | null = null;
	let reportsSubmitted: ReportListResponse | null = null;
	const roles = token ? decodeJwtRoles(token) : [];
	const canModerate = roles.includes(255) || roles.includes(1);

	if (isOwner && reports && reportsPagination) {
		reportsSubmitted = {
			reports,
			pagination: reportsPagination
		};
	}

	if (token && canModerate && (!reportsSubmitted || !isOwner)) {
		const submittedRes = await fetch(`${apiUrl}/api/user/${user.uuid}/reports/submitted`, {
			headers: { Authorization: `Bearer ${token}` }
		});
		if (submittedRes.ok) reportsSubmitted = await submittedRes.json();
	}

	if (token && !isOwner) {
		if (canModerate) {
			const r = await fetch(`${apiUrl}/api/user/${user.uuid}/reports`, {
				headers: { Authorization: `Bearer ${token}` }
			});
			if (r.ok) reportsTarget = await r.json();
		}
	}

	return {
		user,
		pastes: { pastes, pagination },
		reportsTarget,
		reportsSubmitted,
		url: url.href,
		authOptions: options
	};
};
