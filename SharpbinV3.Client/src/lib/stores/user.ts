import { writable } from 'svelte/store';
import type { AuthUser } from '$lib/types/user';

export const user = writable<AuthUser | null>(null);
