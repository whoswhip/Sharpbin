<script lang="ts">
	import type { PageData } from './$types';
	import { displayNames } from '$lib/consts';
	import { user } from '$lib/stores/user';
	import { getToken } from '$lib/utils/auth';
	import { onMount } from 'svelte';
	import { fly } from 'svelte/transition';
	import { encryptAES } from '$lib/utils/encryption';
	import { formatBytes, formatNumber } from '$lib/utils/misc';
	import Dropdown from '$lib/components/Dropdown.svelte';
	import { SvelteURLSearchParams } from 'svelte/reactivity';

	export let data: PageData;

	let error = '';
	let title = '';
	let content = '';
	let selectedSyntax = data.options?.syntaxes?.[0];
	let expiresIn: number = 0;
	let selectedVisibility = data.options?.visibilities?.[0]?.value;
	let password = '';
	let anonymousUpload = false;

	onMount(() => {
		const render = () => {
			if (
				window.turnstile &&
				data.options?.requiresVerification &&
				data.auth?.cf_turnstile_site_key
			) {
				window.turnstile.render('.cf-turnstile', {
					sitekey: data.auth.cf_turnstile_site_key,
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

	const syntaxOptions =
		data.options?.syntaxes?.map((lang: string) => ({
			value: lang,
			label: displayNames[lang] ?? lang.charAt(0).toUpperCase() + lang.slice(1)
		})) ?? [];

	const expiresOptions = [
		{ value: 0, label: 'Never Expire' },
		{ value: 600000, label: 'Expire in 10 Minutes' },
		{ value: 3600000, label: 'Expire in 1 Hour' },
		{ value: 86400000, label: 'Expire in 1 Day' },
		{ value: 604800000, label: 'Expire in 1 Week' },
		{ value: 1209600000, label: 'Expire in 2 Weeks' },
		{ value: 2592000000, label: 'Expire in 1 Month' },
		{ value: 7776000000, label: 'Expire in 3 Months' },
		{ value: 15552000000, label: 'Expire in 6 Months' },
		{ value: 31536000000, label: 'Expire in 1 Year' },
		{ value: 63072000000, label: 'Expire in 2 Years' },
		{ value: 157680000000, label: 'Expire in 5 Years' },
		{ value: 315360000000, label: 'Expire in 10 Years' }
	];

	const visibilityOptions =
		data.options?.visibilities?.map((visibility: { value: number; displayName: string }) => ({
			value: visibility.value,
			label: visibility.displayName
		})) ?? [];

	async function handleSubmit(event: Event) {
		event.preventDefault();
		const params = new SvelteURLSearchParams({
			title: title.trim(),
			syntax: selectedSyntax,
			visibility: selectedVisibility.toString(),
			expiresAt: expiresIn > 0 ? (Date.now() + Number(expiresIn)).toString() : '0'
		});

		if (
			data.options?.requiresVerification &&
			data.auth?.cf_turnstile_site_key &&
			window.turnstile
		) {
			const token = window.turnstile.getResponse();
			if (token) {
				params.append('token', token);
			}
		}

		let body = content;
		if (selectedVisibility === 2) {
			body = await encryptAES(content, password);
		}
		const url = `/api/paste/create?${params.toString()}`;
		const options: RequestInit = {
			method: 'POST',
			headers: { 'Content-Type': 'text/plain' },
			body
		};
		if ($user && !anonymousUpload) {
			const token = getToken();
			if (token) {
				options.headers = {
					...options.headers,
					Authorization: `Bearer ${token}`
				};
			}
		}
		const response = await fetch(url, options);
		if (response.ok) {
			const result = await response.json();
			if (selectedVisibility === 2) {
				const passwordBase64 = btoa(password);
				window.location.href = `/${result.id}#${passwordBase64}`;
				return;
			}
			window.location.href = `/${result.id}`;
		} else {
			if (window.turnstile) {
				window.turnstile.reset();
			}
			if (response.status === 403) {
				error = 'You are banned from creating new pastes.';
			} else {
				const resData = await response.json();
				if (resData.errors) {
					const messages = Object.values(resData.errors).flat();
					error = messages.join('\n');
				} else {
					if (resData.message === 'Verification failed.') {
						if (window.turnstile) {
							window.turnstile.reset();
						}
					}
					error = resData.message || 'Registration failed. Please try again.';
				}
			}
			setInterval(() => {
				error = '';
			}, 5000);
		}
	}
</script>

<svelte:head>
	<title>Create a Paste - Sharpbin</title>
	<meta property="og:title" content="Create a Paste - Sharpbin" />
	<meta property="og:description" content="Create and share your pastes easily with Sharpbin." />
	<meta property="og:type" content="website" />
	<meta property="og:url" content={data.url} />
	<meta property="og:site_name" content="Sharpbin" />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-60px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-4xl font-bold">Create a Paste</h1>
		<form class="mt-4" on:submit|preventDefault={handleSubmit}>
			<input
				type="text"
				placeholder="Title (optional)"
				class="mb-4 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
				spellcheck="false"
				autocomplete="off"
				bind:value={title}
				maxlength={data.options?.maxTitleLength ?? 500}
			/>
			<div class="relative">
				<textarea
					placeholder="Your paste content here..."
					class=" h-64 max-h-[50vh] min-h-10 w-full resize-y rounded rounded-b-none border border-neutral-700 bg-neutral-800 p-2"
					spellcheck="false"
					autocomplete="off"
					bind:value={content}
					on:beforeinput={(e) => {
						if (
							data.options?.maxPasteSize &&
							(new TextEncoder().encode(content).length >= data.options.maxPasteSize ||
								(e.data &&
									new TextEncoder().encode(content + e.data).length > data.options.maxPasteSize))
						) {
							e.preventDefault();
						}
					}}
				></textarea>
				<div
					class="monospace mb-4 flex h-12 items-center justify-between rounded-b border border-neutral-700 bg-neutral-800 p-1 pr-2 pl-2 text-sm text-neutral-400 md:h-8"
				>
					<div class="flex flex-col md:flex-row md:gap-2">
						<span>
							{content.split('\n').length} line{content.split('\n').length !== 1 ? 's' : ''}
						</span>
						<span class="hidden text-neutral-600 md:block">•</span>
						<span>{formatNumber(content.length)} char{content.length !== 1 ? 's' : ''}</span>
					</div>
					<div class="flex flex-col text-center md:flex-row md:gap-2">
						<span class="border-b border-neutral-600 md:border-0">
							{formatBytes(new TextEncoder().encode(content).length)}
						</span>
						<span class="hidden md:block">/</span>
						{formatBytes(data.options?.maxPasteSize ?? 0)}
					</div>
				</div>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-3 md:gap-2">
				<Dropdown
					options={syntaxOptions}
					bind:value={selectedSyntax}
					placeholder="Select syntax..."
					searchable={true}
				/>
				<Dropdown
					options={expiresOptions}
					bind:value={expiresIn}
					placeholder="Select expiration..."
				/>
				<Dropdown
					options={visibilityOptions}
					bind:value={selectedVisibility}
					placeholder="Select visibility..."
				/>
			</div>
			{#if selectedVisibility === 2}
				<input
					type="password"
					placeholder="Password for private paste"
					class="w-full rounded border border-neutral-700 bg-neutral-800 p-2"
					spellcheck="false"
					autocomplete="off"
					bind:value={password}
				/>
			{/if}
			{#if $user}
				<label
					class="flex w-full items-center gap-2 rounded border border-neutral-700 bg-neutral-800 p-2"
				>
					<input
						type="checkbox"
						bind:checked={anonymousUpload}
						class="h-4 w-4 rounded border-neutral-600 bg-neutral-700 text-neutral-500"
					/>
					<span>Upload anonymously</span>
				</label>
			{/if}
			{#if data.options?.requiresVerification && data.auth?.cf_turnstile_site_key}
				<div
					class="mt-2 min-h-16.25 flex w-auto items-center justify-center rounded border border-neutral-700 bg-neutral-800 p-2 pb-1"
				>
					<div class="cf-turnstile" data-sitekey={data.auth.cf_turnstile_site_key}></div>
				</div>
			{/if}
			<button
				type="submit"
				disabled={$user?.roles && $user.roles.includes(403)}
				class="mt-2 w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900 disabled:cursor-not-allowed disabled:bg-neutral-950/50 disabled:text-neutral-400"
				>Create Paste</button
			>
			{#if error}
				<div
					transition:fly={{ y: 40, duration: 300 }}
					class="mt-2 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200"
				>
					{error}
				</div>
			{/if}
			{#if $user?.roles && $user.roles.includes(403)}
				<div
					transition:fly={{ y: 40, duration: 300 }}
					class="mt-2 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200"
				>
					You are banned from creating new pastes.
				</div>
			{/if}
		</form>
	</div>
</main>
