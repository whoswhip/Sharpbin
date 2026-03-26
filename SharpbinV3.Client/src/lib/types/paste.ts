import type { Author } from './author';

export interface Paste {
	id: string;
	uuid: string;
	createdAt: number;
	title: string | null;
	size: number;
	trueSize: number;
	isCompressed: boolean;
	views: number;
	syntax: string;
	visibility: 0 | 1 | 2;
	expiresAt: number;
	editedAt: number | null;
	reportCount: number | null;
	author: Author | null;
}
