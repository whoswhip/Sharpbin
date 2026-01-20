<script lang="ts">
	import { user } from '$lib/stores/user';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { clearTokens } from '$lib/utils/auth';
	import type { PageData } from '../../routes/$types';

	function logout() {
		clearTokens();
		user.set(null);
		window.location.href = '/';
	}

	export let data: PageData;

	let currentPath = page.url.pathname;
	let returnParam =
		currentPath !== '/' && !currentPath.startsWith('/login') && !currentPath.startsWith('/register')
			? `?return=${encodeURIComponent(page.url.pathname + page.url.search)}`
			: '';
</script>

<div class="top-0 left-0 z-100 h-15 w-full bg-neutral-900">
	<div class="mx-auto flex h-15 w-[95%] max-w-7xl items-center py-2">
		<a href={resolve('/')} class="text-xl font-bold text-white hover:text-neutral-300">Sharpbin</a>
		{#if $user}
			<div class="ml-auto flex items-center space-x-4">
				{#if $user.roles.includes(1) || $user.roles.includes(255)}
					<a
						href={resolve('/reports')}
						class="rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800">Reports</a
					>
				{/if}
				<a
					href={resolve(`/user/${$user.username}`)}
					class="rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800">Profile</a
				>
				<button
					on:click={logout}
					class="cursor-pointer rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800"
					>Logout</button
				>
			</div>
		{:else}
			<div class="ml-auto flex items-center space-x-4">
				<a
					href={resolve(`/login${returnParam}`)}
					class="rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800">Login</a
				>
				<!-- eslint-disable svelte/no-navigation-without-resolve -->
				<a
					href={data.options?.registration_enabled ? resolve(`/register${returnParam}`) : '#'}
					class="rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800 {data.options
						?.registration_enabled
						? ''
						: 'cursor-not-allowed bg-neutral-800 text-neutral-500!'}">Register</a
				>
				<!-- eslint-enable svelte/no-navigation-without-resolve -->
			</div>
		{/if}
	</div>
</div>
