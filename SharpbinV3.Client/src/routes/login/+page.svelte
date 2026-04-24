<script lang="ts">
	import { resolve } from '$app/paths';
	import { setTokens, startTokenRefreshInterval } from '$lib/utils/auth';
	import { extractError } from '$lib/utils/misc';
	import { onMount } from 'svelte';
	import type { PageData } from './$types';

	let username = $state('');
	let password = $state('');
	let error = $state('');
	let totpEnabled = $state(false);
	let totpCode = $state('');
	interface Props {
		data: PageData;
	}

	let { data }: Props = $props();

	onMount(() => {
		const render = () => {
			if (window.turnstile && data.options?.cf_turnstile_site_key) {
				window.turnstile.render('.cf-turnstile', {
					sitekey: data.options.cf_turnstile_site_key,
					theme: 'dark',
					size: 'flexible',
					appearence: 'interaction-only'
				});
			}
		};

		if (window.turnstile) {
			render();
		} else {
			window.addEventListener('turnstile:loaded', render, { once: true });
		}

		return () => {
			window.removeEventListener('turnstile:loaded', render);
		};
	});

	async function login(event: Event) {
		event.preventDefault();
		const body: { username: string; password: string; token?: string; totpcode?: string } = {
			username,
			password
		};

		if (data.options?.cf_turnstile_site_key && window.turnstile) {
			const token = window.turnstile.getResponse();
			if (token) {
				body.token = token;
			}
		}

		if (totpEnabled && totpCode) {
			body.totpcode = totpCode;
		}

		const res = await fetch('/api/auth/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		});
		if (res.ok) {
			const data = await res.json();
			if (data.token && data.refreshToken) {
				setTokens(data.token, data.refreshToken);
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
			const resData = await res.json();
			if (window.turnstile) {
				window.turnstile.reset();
			}
			error = extractError(resData) || 'Login failed. Please try again.';
			if (error === 'TOTP code is required.') {
				totpEnabled = true;
			}
		}
	}
</script>

<svelte:head>
	<title>Login - Sharpbin</title>
	<meta
		name="description"
		content="Login to your Sharpbin account to manage your pastes and settings."
	/>
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-full max-w-md rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-3xl font-bold">Login</h1>
		<form onsubmit={login} class="space-y-4">
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
			{#if totpEnabled}
				<input
					type="text"
					placeholder="TOTP Code"
					bind:value={totpCode}
					maxlength="6"
					inputmode="numeric"
					pattern="[0-9]*"
					required
					oninput={(e) => {
						if (e.target instanceof HTMLInputElement) {
							e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
							totpCode = e.target.value;
						}
					}}
					class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
				/>
			{/if}
			{#if data.options?.cf_turnstile_site_key}
				<div class="cf-turnstile w-full"></div>
			{/if}
			<button
				type="submit"
				class="w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900"
			>
				Login
			</button>
			{#if error}
				<div
					class="rounded border border-red-900 bg-red-950 p-2 text-sm whitespace-pre-line text-red-200"
				>
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
