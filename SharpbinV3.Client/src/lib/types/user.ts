import type { Paste } from './paste';
import type { Pagination } from './pagination';

export interface User {
	uid: number;
	uuid: string;
	username: string;
	displayName: string | null;
	email: string | null;
	emailVerified: boolean;
	lastLogin: number | null;
	roles: number; // bitfield; 5 = User | Admin
	isBanned: boolean;
	visibility: 0 | 1 | 2;
	pastes: Paste[] | null;
	pagination: Pagination | null;
}

export interface AuthUser extends User {
	totpEnabled: boolean;
}

export interface JWTUser {
	uuid: string;
	username: string;
	displayname: string;
	totpEnabled: boolean;
	roles: number;
	isBanned: boolean;
}
