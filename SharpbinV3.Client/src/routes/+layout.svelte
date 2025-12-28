<script lang="ts">
	import { onMount } from 'svelte';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import Navbar from '$lib/components/Navbar.svelte';
	import { user } from '$lib/stores/user';
	import { startTokenRefreshInterval, getToken, refreshTokenIfNeeded } from '$lib/utils/auth';

	if (typeof window !== 'undefined') {
		startTokenRefreshInterval();
	}

	onMount(async () => {
		await refreshTokenIfNeeded();
		const token = getToken();
		if (!token) return;

		const res = await fetch('/api/user/me', {
			headers: { Authorization: `Bearer ${token}` }
		});

		if (res.ok) {
			user.set(await res.json());
		} else {
			user.set(null);
		}
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<Navbar />
<slot />
