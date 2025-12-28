import type { Author } from './author';

export interface Paste {
	id: string;
	uuid: string;
	title: string | null;
	size: number;
	trueSize: number;
	isCompressed: boolean;
	views: number;
	syntax: string;
	visibility: 0 | 1 | 2;
	expiresAt: number;
	author: Author | null;
}
