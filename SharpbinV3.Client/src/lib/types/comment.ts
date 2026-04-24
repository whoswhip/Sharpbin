import type { Author } from './author';

export type CommentReaction = 1 | 2 | null;

export interface CommentAuthor extends Author {
	displayName?: string | null;
	roles?: number;
	isBanned?: boolean;
}

export interface PasteComment {
	id: number;
	parentCommentID: number | null;
	content: string | null;
	storedSize: number;
	originalSize: number;
	isCompressed: boolean;
	createdAt: number;
	updatedAt: number | null;
	likes: number;
	dislikes: number;
	userReaction: CommentReaction;
	author: CommentAuthor | null;
}

export interface CommentReactionResult {
	commentID: number;
	likes: number;
	dislikes: number;
	userReaction: CommentReaction;
}

export interface CommentTreeNode extends PasteComment {
	children: CommentTreeNode[];
}
