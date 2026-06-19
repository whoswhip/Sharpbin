<script lang="ts">
	import { resolve } from '$app/paths';
	import { extractError } from '$lib/utils/misc';
	import { Check, X } from '@lucide/svelte';
	import { slide, fade } from 'svelte/transition';
	import type { PageData } from './$types';

	interface Props {
		data: PageData;
	}

	let { data }: Props = $props();
	let password = $state('');
	let confirmPassword = $state('');
	let totpCode = $state('');
	let error = $state('');
	let message = $state('');
	let complete = $state(false);
	let loading = $state(false);
	let passwordFocused = $state(false);
	let passwordChecks = $state({
		minLength: false,
		maxLength: false,
		upper: false,
		lower: false,
		number: false
	});
	let passwordValid = $state(false);

	function validatePassword(pw: string) {
		passwordChecks.minLength = pw.length >= 8;
		passwordChecks.maxLength = pw.length <= 128;
		passwordChecks.upper = /[A-Z]/.test(pw);
		passwordChecks.lower = /[a-z]/.test(pw);
		passwordChecks.number = /[0-9]/.test(pw);
		passwordValid =
			passwordChecks.minLength &&
			passwordChecks.maxLength &&
			passwordChecks.upper &&
			passwordChecks.lower &&
			passwordChecks.number;
	}

	$effect(() => {
		validatePassword(password);
	});

	async function submit(event: Event) {
		event.preventDefault();
		error = '';
		message = '';

		if (!password || !confirmPassword) {
			error = 'Both password fields are required.';
			return;
		}
		if (password !== confirmPassword) {
			error = 'Passwords do not match.';
			return;
		}
		if (!passwordValid) {
			error =
				'Password should have at least 8 characters, no more than 128 characters, including uppercase, lowercase, and digits.';
			return;
		}

		loading = true;
		try {
			const res = await fetch('/api/auth/password/reset', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					token: data.token,
					newPassword: password,
					...(data.requiresTotp ? { totpCode } : {})
				})
			});
			const json = await res.json().catch(() => ({}));
			if (!res.ok) {
				error = extractError(json) || 'Password reset failed.';
				return;
			}
			complete = true;
			message = json.message || 'Password reset successfully.';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Reset Password - Sharpbin</title>
	<meta name="description" content="Set a new password for your Sharpbin account." />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-full max-w-md rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		{#if complete}
			<h1 class="mb-2 text-center text-3xl font-bold">Password Reset</h1>
			<p class="text-center text-sm text-neutral-400">{message}</p>
			<p class="mt-4 text-center text-sm text-neutral-400">
				<a
					href={resolve('/login')}
					class="text-neutral-200 transition-colors duration-200 hover:text-white">Back to login</a
				>
			</p>
		{:else}
			<h1 class="mb-2 text-center text-3xl font-bold">Reset Password</h1>
			<p class="mb-6 text-center text-sm text-neutral-400">
				{#if data.username}
					Reset the password for {data.username}.
				{:else}
					Set a new password for your account.
				{/if}
			</p>
			<form onsubmit={submit} class="space-y-4">
				<input
					type="password"
					placeholder="New password"
					bind:value={password}
					autocomplete="new-password"
					required
					onfocus={() => (passwordFocused = true)}
					onblur={() => (passwordFocused = false)}
					class="focus:bg-neutral-750 w-full rounded border border-neutral-700 bg-neutral-800 p-2 placeholder-neutral-500 transition-colors duration-200 focus:border-neutral-600"
				/>
				{#if passwordFocused}
					<ul
						transition:slide
						class="space-y-2 rounded border border-neutral-700 bg-neutral-800 p-3 text-sm"
					>
						<li
							class="flex items-center gap-2 {passwordChecks.minLength
								? 'text-green-400'
								: 'text-red-400'}"
						>
							{#if passwordChecks.minLength}<Check class="h-4 w-4" />{:else}<X
									class="h-4 w-4"
								/>{/if}
							At least 8 characters
						</li>
						<li
							class="flex items-center gap-2 {passwordChecks.maxLength
								? 'text-green-400'
								: 'text-red-400'}"
						>
							{#if passwordChecks.maxLength}<Check class="h-4 w-4" />{:else}<X
									class="h-4 w-4"
								/>{/if}
							No more than 128 characters
						</li>
						<li
							class="flex items-center gap-2 {passwordChecks.upper
								? 'text-green-400'
								: 'text-red-400'}"
						>
							{#if passwordChecks.upper}<Check class="h-4 w-4" />{:else}<X class="h-4 w-4" />{/if}
							At least one uppercase letter
						</li>
						<li
							class="flex items-center gap-2 {passwordChecks.lower
								? 'text-green-400'
								: 'text-red-400'}"
						>
							{#if passwordChecks.lower}<Check class="h-4 w-4" />{:else}<X class="h-4 w-4" />{/if}
							At least one lowercase letter
						</li>
						<li
							class="flex items-center gap-2 {passwordChecks.number
								? 'text-green-400'
								: 'text-red-400'}"
						>
							{#if passwordChecks.number}<Check class="h-4 w-4" />{:else}<X class="h-4 w-4" />{/if}
							At least one number
						</li>
					</ul>
				{/if}
				<input
					type="password"
					placeholder="Confirm new password"
					bind:value={confirmPassword}
					autocomplete="new-password"
					required
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
				{#if data.requiresTotp}
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
				<button
					type="submit"
					disabled={loading || !passwordValid || password !== confirmPassword}
					class="w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900 disabled:opacity-50"
				>
					{loading ? 'Updating...' : 'Reset Password'}
				</button>
				{#if error}
					<div
						class="rounded border border-red-900 bg-red-950 p-2 text-sm whitespace-pre-line text-red-200"
					>
						{error}
					</div>
				{/if}
			</form>
		{/if}
	</div>
</main>
