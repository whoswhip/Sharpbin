<script lang="ts">
	import { user } from '$lib/stores/user';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	function logout() {
		localStorage.removeItem('token');
		localStorage.removeItem('refreshToken');
		user.set(null);
		window.location.href = '/';
	}

	$: currentPath = page.url.pathname;
	$: returnParam =
		currentPath !== '/' ? `?return=${encodeURIComponent(page.url.pathname + page.url.search)}` : '';
</script>

<div class="fixed top-0 left-0 z-100 h-15 w-full bg-neutral-900">
	<div class="mx-auto flex h-15 max-w-5xl items-center px-4 py-2">
		<a href={resolve('/')} class="text-xl font-bold text-white hover:text-neutral-300">Sharpbin</a>
		{#if $user}
			<div class="ml-auto flex items-center space-x-4">
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
				<a
					href={resolve(`/register${returnParam}`)}
					class="rounded bg-neutral-700 px-3 py-1 text-white hover:bg-neutral-800">Register</a
				>
			</div>
		{/if}
	</div>
</div>
