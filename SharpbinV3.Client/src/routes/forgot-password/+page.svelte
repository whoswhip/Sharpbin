<script lang="ts">
	import { resolve } from '$app/paths';
	import { extractError } from '$lib/utils/misc';
	import { onMount } from 'svelte';
	import type { PageData } from './$types';

	let email = $state('');
	let error = $state('');
	let message = $state('');

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

	async function submit(event: Event) {
		event.preventDefault();
		error = '';
		message = '';

		const body: { email: string; token?: string } = { email };
		if (data.options?.cf_turnstile_site_key && window.turnstile) {
			const token = window.turnstile.getResponse();
			if (token) body.token = token;
		}

		const res = await fetch('/api/auth/password/forgot', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		});

		const json = await res.json().catch(() => ({}));
		if (!res.ok) {
			if (window.turnstile) window.turnstile.reset();
			error = extractError(json) || 'Request failed.';
			return;
		}

		if (window.turnstile) window.turnstile.reset();
		message = json.message || 'If an account exists for that email, a reset link has been sent.';
		email = '';
	}
</script>

<svelte:head>
	<title>Forgot Password - Sharpbin</title>
	<meta name="description" content="Request a password reset link for your Sharpbin account." />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-full max-w-md rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-2 text-center text-3xl font-bold">Forgot Password</h1>
		<p class="mb-6 text-center text-sm text-neutral-400">
			Enter the email address on your account and we’ll send a reset link if one exists.
		</p>
		<form onsubmit={submit} class="space-y-4">
			<input
				type="email"
				placeholder="Email"
				bind:value={email}
				autocomplete="email"
				required
				class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
			/>
			{#if data.options?.cf_turnstile_site_key}
				<div class="cf-turnstile w-full"></div>
			{/if}
			<button
				type="submit"
				class="w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900"
			>
				Send Reset Link
			</button>
			{#if error}
				<div
					class="rounded border border-red-900 bg-red-950 p-2 text-sm whitespace-pre-line text-red-200"
				>
					{error}
				</div>
			{/if}
			{#if message}
				<div
					class="rounded border border-green-900 bg-green-950 p-2 text-sm whitespace-pre-line text-green-200"
				>
					{message}
				</div>
			{/if}
		</form>
		<p class="mt-4 text-center text-sm text-neutral-400">
			<a
				href={resolve('/login')}
				class="text-neutral-200 transition-colors duration-200 hover:text-white">Back to login</a
			>
		</p>
	</div>
</main>
