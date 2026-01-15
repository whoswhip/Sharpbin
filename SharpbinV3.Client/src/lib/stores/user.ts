import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import type { AuthUser } from '$lib/types/user';

let initial: AuthUser | null = null;

if (browser) {
	try {
		const stored = localStorage.getItem('user');
		if (stored) {
			const parsed = JSON.parse(stored);
			if (parsed && 'user' in parsed && typeof parsed.user === 'object') {
				const { user: nestedUser, ...rest } = parsed;
				initial = { ...rest, ...nestedUser };
			} else {
				initial = parsed;
			}
		}
	} catch {
		/* empty */
	}
}

export const user = writable<AuthUser | null>(initial);

if (browser) {
	user.subscribe((val) => {
		if (val) localStorage.setItem('user', JSON.stringify(val));
		else localStorage.removeItem('user');
	});
}
