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

	export let data: LayoutData;

	if (typeof window !== 'undefined') {
		startTokenRefreshInterval();
		window.turnstileLoaded = () => {
			window.dispatchEvent(new CustomEvent('turnstile:loaded'));
		};
	}

	onMount(async () => {
		await refreshTokenIfNeeded();
		const token = getToken();
		if (!token) {
			user.set(null);
			return;
		}

		const res = await fetch('/api/user/me', {
			headers: { Authorization: `Bearer ${token}` }
		});

		if (res.ok) {
			const me = await res.json();
			let userData = me;
			if (me && 'user' in me && typeof me.user === 'object') {
				const { user: nestedUser, ...rest } = me;
				userData = { ...rest, ...nestedUser };
			}
			user.set({ ...userData, totpEnabled: parseTotpEnabled(getToken()) });
		} else {
			user.set(null);
		}
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
<!-- <div class="h-15 w-full"></div> -->
<slot />
<Footer />

<ModalHost />
