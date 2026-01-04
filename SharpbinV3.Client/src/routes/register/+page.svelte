<script lang="ts">
	import { goto } from '$app/navigation';
	import { setTokens, startTokenRefreshInterval } from '$lib/utils/auth';
	import { Check, X } from '@lucide/svelte';
	import { slide, fade } from 'svelte/transition';
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import type { PageData } from './$types';

	let username = '';
	let password = '';
	let confirmPassword = '';
	let email = '';
	let displayName = '';
	let error = '';

	let passwordFocused = false;
	let passwordChecks = {
		length: false,
		upper: false,
		lower: false,
		number: false
	};
	let passwordValid = false;
	let loading = false;

	export let data: PageData;

	onMount(() => {
		const render = () => {
			if (window.turnstile && data.options?.cf_turnstile_site_key) {
				window.turnstile.render('.cf-turnstile', {
					sitekey: data.options.cf_turnstile_site_key,
					theme: 'dark'
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

	function validatePassword(pw: string) {
		passwordChecks.length = pw.length >= 8;
		passwordChecks.upper = /[A-Z]/.test(pw);
		passwordChecks.lower = /[a-z]/.test(pw);
		passwordChecks.number = /[0-9]/.test(pw);
		passwordValid =
			passwordChecks.length &&
			passwordChecks.upper &&
			passwordChecks.lower &&
			passwordChecks.number;
	}

	$: validatePassword(password);

	async function register() {
		if (!passwordValid || password !== confirmPassword) return;
		loading = true;
		error = '';
		const body: Record<string, unknown> = { username, password, email, displayName };
		if (data.options?.cf_turnstile_site_key && window.turnstile) {
			const token = window.turnstile.getResponse();
			if (token) body.token = token;
		}
		const res = await fetch('/api/auth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		});
		if (res.ok) {
			const data = await res.json();
			if (data.token && data.refreshToken) {
				setTokens(data.token, data.refreshToken);
				startTokenRefreshInterval();
				goto(resolve('/'));
			} else {
				const urlParams = new URLSearchParams(window.location.search);
				const returnUrl = urlParams.get('return');
				if (returnUrl) {
					goto(resolve(`/login?return=${encodeURIComponent(returnUrl)}`));
				} else {
					goto(resolve('/login'));
				}
			}
		} else {
			const payload = await res.json().catch(() => null);
			error = payload?.message ?? 'Registration failed';
		}
		loading = false;
	}
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div class="w-full max-w-md rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-3xl font-bold">Register</h1>
		<form on:submit|preventDefault={register} class="space-y-4">
			<input
				type="text"
				placeholder="Username"
				bind:value={username}
				autocomplete="username"
				required
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			<div>
				<input
					type="email"
					placeholder="Email (optional)"
					bind:value={email}
					autocomplete="email"
					class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
				/>
			</div>
			<div>
				<input
					type="text"
					placeholder="Display Name (optional)"
					bind:value={displayName}
					autocomplete="name"
					class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
				/>
			</div>
			<input
				type="password"
				placeholder="Password"
				bind:value={password}
				required
				on:focus={() => (passwordFocused = true)}
				on:blur={() => (passwordFocused = false)}
				autocomplete="new-password"
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			{#if passwordFocused}
				<ul
					transition:slide
					class="space-y-2 rounded border border-neutral-700 bg-neutral-800 p-3 text-sm"
				>
					<li
						class="flex items-center gap-2 {passwordChecks.length
							? 'text-green-400'
							: 'text-red-400'}"
					>
						{#if passwordChecks.length}
							<Check class="h-4 w-4" />
						{:else}
							<X class="h-4 w-4" />
						{/if}
						At least 8 characters
					</li>
					<li
						class="flex items-center gap-2 {passwordChecks.upper
							? 'text-green-400'
							: 'text-red-400'}"
					>
						{#if passwordChecks.upper}
							<Check class="h-4 w-4" />
						{:else}
							<X class="h-4 w-4" />
						{/if}
						At least one uppercase letter
					</li>
					<li
						class="flex items-center gap-2 {passwordChecks.lower
							? 'text-green-400'
							: 'text-red-400'}"
					>
						{#if passwordChecks.lower}
							<Check class="h-4 w-4" />
						{:else}
							<X class="h-4 w-4" />
						{/if}
						At least one lowercase letter
					</li>
					<li
						class="flex items-center gap-2 {passwordChecks.number
							? 'text-green-400'
							: 'text-red-400'}"
					>
						{#if passwordChecks.number}
							<Check class="h-4 w-4" />
						{:else}
							<X class="h-4 w-4" />
						{/if}
						At least one number
					</li>
				</ul>
			{/if}
			<input
				type="password"
				placeholder="Confirm Password"
				bind:value={confirmPassword}
				required
				autocomplete="new-password"
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			{#if confirmPassword && password !== confirmPassword}
				<div
					transition:fade
					class="rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200"
				>
					Passwords do not match.
				</div>
			{/if}
			{#if data.options?.cf_turnstile_site_key}
				<div class="flex w-full justify-center">
					<div class="cf-turnstile"></div>
				</div>
			{/if}
			<button
				type="submit"
				disabled={!passwordValid || password !== confirmPassword || loading}
				class="w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900 disabled:cursor-not-allowed disabled:bg-neutral-800 disabled:text-neutral-500"
			>
				{loading ? 'Registering...' : 'Register'}
			</button>
			{#if error}
				<div class="rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
					{error}
				</div>
			{/if}
		</form>
		<p class="mt-4 text-center text-sm text-neutral-400">
			Already have an account? <a
				href={resolve('/login')}
				class="text-neutral-200 transition-colors duration-200 hover:text-white">Login</a
			>
		</p>
	</div>
</main>
