import type { Paste } from './paste';
import type { Pagination } from './pagination';

export interface User {
	uid: number;
	uuid: string;
	username: string;
	displayName: string | null;
	email: string | null;
	lastLogin: number | null;
	roles: number[];
	visibility: 0 | 1 | 2;
	pastes: Paste[] | null;
	pagination: Pagination | null;
}
