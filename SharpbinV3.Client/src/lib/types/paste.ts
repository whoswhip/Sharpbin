import type { Author } from './author';

export type PasteReaction = 1 | 2 | null;

export interface Paste {
	id: string;
	uuid: string;
	createdAt: number;
	title: string | null;
	sizeStored: number;
	originalSize: number;
	isCompressed: boolean;
	views: number;
	syntax: string;
	visibility: 0 | 1 | 2;
	expiresAt: number;
	editedAt: number | null;
	likes: number;
	dislikes: number;
	userReaction: PasteReaction;
	reportCount: number | null;
	author: Author | null;
}
