<script lang="ts">
	import { resolve } from '$app/paths';
	let username = '';
	let password = '';
	let error = '';
	import { setTokens, startTokenRefreshInterval } from '$lib/utils/auth';

	async function login() {
		const res = await fetch('/api/auth/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username, password })
		});
		if (res.ok) {
			const data = await res.json();
			if (data.result.token && data.result.refreshToken) {
				setTokens(data.result.token, data.result.refreshToken);
				startTokenRefreshInterval();
			}
			const urlParams = new URLSearchParams(window.location.search);
			const returnUrl = urlParams.get('return');
			if (returnUrl) {
				window.location.href = returnUrl;
				return;
			}
			window.location.href = '/';
		} else {
			error = 'Invalid username or password';
		}
	}
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div class="w-full max-w-md rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-3xl font-bold">Login</h1>
		<form on:submit|preventDefault={login} class="space-y-4">
			<input
				type="text"
				placeholder="Username"
				bind:value={username}
				autocomplete="username"
				required
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			<input
				type="password"
				placeholder="Password"
				bind:value={password}
				required
				autocomplete="current-password"
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			<button
				type="submit"
				class="w-full rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900"
			>
				Login
			</button>
			{#if error}
				<div class="rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
					{error}
				</div>
			{/if}
		</form>
		<p class="mt-4 text-center text-sm text-neutral-400">
			Don't have an account? <a
				href={resolve('/register')}
				class="text-neutral-200 transition-colors duration-200 hover:text-white">Register</a
			>
		</p>
	</div>
</main>
