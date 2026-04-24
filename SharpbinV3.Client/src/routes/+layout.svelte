<script lang="ts">
	import { onMount } from 'svelte';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import Navbar from '$lib/components/Navbar.svelte';
	import Footer from '$lib/components/Footer.svelte';
	import ModalHost from '$lib/components/ModalHost.svelte';
	import { user } from '$lib/stores/user';
	import { startTokenRefreshInterval, getToken, refreshTokenIfNeeded } from '$lib/utils/auth';
	import { parseTotpEnabled } from '$lib/utils/totp';
	import { page } from '$app/state';
	import type { LayoutData } from './$types';

	interface Props {
		data: LayoutData;
		children?: import('svelte').Snippet;
	}

	let { data, children }: Props = $props();

	async function syncUserFromToken() {
		const token = getToken();
		if (!token) {
			user.set(null);
			return;
		}

		try {
			const res = await fetch('/api/user/me', {
				headers: { Authorization: `Bearer ${token}` }
			});

			if (!res.ok) {
				if (res.status === 401 || res.status === 403) {
					user.set(null);
				}
				return;
			}

			const me = await res.json();
			let userData = me;
			if (me && 'user' in me && typeof me.user === 'object') {
				const { user: nestedUser, ...rest } = me;
				userData = { ...rest, ...nestedUser };
			}
			user.set({ ...userData, totpEnabled: parseTotpEnabled(getToken()) });
		} catch {
			return;
		}
	}

	if (typeof window !== 'undefined') {
		startTokenRefreshInterval();
		window.turnstileLoaded = () => {
			window.dispatchEvent(new CustomEvent('turnstile:loaded'));
		};
	}

	onMount(() => {
		const refreshAndSync = async () => {
			await refreshTokenIfNeeded();
			await syncUserFromToken();
		};

		const handleFocus = () => {
			void refreshAndSync();
		};

		const handleVisibilityChange = () => {
			if (document.visibilityState === 'visible') {
				void refreshAndSync();
			}
		};

		const handleTokensUpdated = () => {
			void syncUserFromToken();
		};

		const handleTokensCleared = () => {
			user.set(null);
		};

		void refreshAndSync();

		window.addEventListener('focus', handleFocus);
		document.addEventListener('visibilitychange', handleVisibilityChange);
		window.addEventListener('auth:tokens-updated', handleTokensUpdated);
		window.addEventListener('auth:tokens-cleared', handleTokensCleared);

		return () => {
			window.removeEventListener('focus', handleFocus);
			document.removeEventListener('visibilitychange', handleVisibilityChange);
			window.removeEventListener('auth:tokens-updated', handleTokensUpdated);
			window.removeEventListener('auth:tokens-cleared', handleTokensCleared);
		};
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	{#if data.options?.cf_turnstile_site_key && (page.url.pathname === '/login' || page.url.pathname === '/register' || page.url.pathname === '/')}
		<script
			src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=turnstileLoaded"
			async
			defer
		></script>
	{/if}
</svelte:head>

<Navbar {data} />
{@render children?.()}
<Footer />

<ModalHost />
