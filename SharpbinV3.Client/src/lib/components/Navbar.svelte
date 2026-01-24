<script lang="ts">
	import { user } from '$lib/stores/user';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { clearTokens } from '$lib/utils/auth';
	import logo from '$lib/assets/favicon.svg';
	import type { PageData } from '../../routes/$types';
	import { slide } from 'svelte/transition';
	import { Menu, X } from '@lucide/svelte';

	function logout() {
		clearTokens();
		user.set(null);
		window.location.href = '/';
	}

	export let data: PageData;

	let menuOpen = false;

	let currentPath = page.url.pathname;
	let returnParam =
		currentPath !== '/' && !currentPath.startsWith('/login') && !currentPath.startsWith('/register')
			? `?return=${encodeURIComponent(page.url.pathname + page.url.search)}`
			: '';
</script>

<div class="top-0 left-0 z-100 h-15 w-full bg-neutral-900">
	<div class="mx-auto hidden h-15 w-[95%] max-w-7xl items-center py-2 md:flex">
		<div>
			<a href={resolve('/')} class="text-xl font-bold text-white hover:text-neutral-300">Sharpbin</a
			>
			<a href={resolve('/recent')} class="ml-6 text-white hover:text-neutral-300">Recent Pastes</a>
		</div>
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

	<div class="mx-auto flex h-15 w-[90%] max-w-7xl items-center py-2 md:hidden">
		<a href={resolve('/')} class="group">
			<img src={logo} alt="Sharpbin Logo" class="h-8 w-8 group-hover:opacity-80" />
		</a>
		<button
			class="ml-auto flex h-10 w-10 items-center justify-center rounded border border-neutral-700 bg-neutral-800 p-2 hover:bg-neutral-700 focus:outline-none"
			on:click={() => (menuOpen = !menuOpen)}
			aria-label="Toggle Menu"
			aria-expanded={menuOpen}
		>
			{#if menuOpen}
				<X class="h-6 w-6 text-white" />
			{:else}
				<Menu class="h-6 w-6 text-white" />
			{/if}
		</button>
	</div>
	{#if menuOpen}
		<div
			class="mx-auto mb-2 w-full rounded-b border-b border-neutral-800 bg-neutral-900 px-2 py-3 md:hidden"
			in:slide={{ duration: 180 }}
			out:slide={{ duration: 180 }}
			style="z-index:1000;position:relative;"
		>
			<a
				href={resolve('/recent')}
				class="block w-full rounded bg-neutral-800 px-3 py-2 text-center text-neutral-100 transition-colors hover:bg-neutral-700"
				on:click={() => (menuOpen = false)}>Recent Pastes</a
			>
			{#if $user}
				{#if $user.roles.includes(1) || $user.roles.includes(255)}
					<a
						href={resolve('/reports')}
						class="mt-1 block w-full rounded bg-neutral-800 px-3 py-2 text-center text-neutral-100 transition-colors hover:bg-neutral-700"
						on:click={() => (menuOpen = false)}>Reports</a
					>
				{/if}
				<a
					href={resolve(`/user/${$user.username}`)}
					class="mt-1 block w-full rounded bg-neutral-800 px-3 py-2 text-center text-neutral-100 transition-colors hover:bg-neutral-700"
					on:click={() => (menuOpen = false)}>Profile</a
				>
				<button
					on:click={() => {
						logout();
						menuOpen = false;
					}}
					class="mt-1 w-full rounded bg-neutral-800 px-3 py-2 text-center text-neutral-100 transition-colors hover:bg-neutral-700"
					>Logout</button
				>
			{:else}
				<a
					href={resolve(`/login${returnParam}`)}
					class="mt-1 block w-full rounded bg-neutral-800 px-3 py-2 text-neutral-100 transition-colors hover:bg-neutral-700"
					on:click={() => (menuOpen = false)}>Login</a
				>
				<!-- eslint-disable svelte/no-navigation-without-resolve -->
				<a
					href={data.options?.registration_enabled ? resolve(`/register${returnParam}`) : '#'}
					class="mt-1 block w-full rounded px-3 py-2 text-neutral-100 transition-colors hover:bg-neutral-700 {data
						.options?.registration_enabled
						? ''
						: 'cursor-not-allowed bg-neutral-900 text-neutral-500'}"
					on:click={() => (menuOpen = false)}>Register</a
				>
				<!-- eslint-enable svelte/no-navigation-without-resolve -->
			{/if}
		</div>
	{/if}
</div>
