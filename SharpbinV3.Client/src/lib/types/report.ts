import type { Pagination } from './pagination';

export interface Report {
	reportID: number;
	type: number;
	status: number;
	description: string | null;
	createdAt: number;
	updatedAt: number | null;
	reporterUUID: string;
	reporterUsername?: string | null;
	reporterDisplayName?: string | null;
	targetType: number;
	pastePID: number | null;
	pasteId?: string | null;
	pasteTitle?: string | null;
	userUUID: string | null;
	targetUsername?: string | null;
	targetDisplayName?: string | null;
}

export interface ReportListResponse {
	reports: Report[];
	pagination: Pagination;
}

export const reportTypeLabels = ['CopyrightViolation', 'IllegalContent', 'Fraud', 'Other'] as const;

export const reportStatusLabels = ['Open', 'Closed'] as const;

export const reportTargetLabels = ['Paste', 'User', 'Comment'] as const;
