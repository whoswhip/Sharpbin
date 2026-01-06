<script lang="ts">
	import type { PageData } from './$types';
	import { displayNames } from '$lib/consts';
	import { user } from '$lib/stores/user';
	import { getToken } from '$lib/utils/auth';
	import { fly } from 'svelte/transition';
	import { encryptAES } from '$lib/utils/encryption';
	import Dropdown from '$lib/components/Dropdown.svelte';

	export let data: PageData;

	let error = '';
	let title = '';
	let content = '';
	let selectedSyntax = data.options?.syntaxes?.[0];
	let expiresIn: number = 0;
	let selectedVisibility = data.options?.visibilities?.[0]?.value;
	let password = '';

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
		const params = new URLSearchParams({
			title: title.trim(),
			syntax: selectedSyntax,
			visibility: selectedVisibility.toString(),
			expiresAt: expiresIn > 0 ? (Date.now() + Number(expiresIn)).toString() : '0'
		});
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
		if ($user) {
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
			error = 'Failed to create paste. Please try again.';
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
	<meta property="og:url" content="{data.url}" />
	<meta property="og:site_name" content="Sharpbin" />
</svelte:head>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
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
			<textarea
				placeholder="Your paste content here..."
				class="mb-4 h-64 max-h-[50vh] min-h-10 w-full resize-y rounded border border-neutral-700 bg-neutral-800 p-2"
				spellcheck="false"
				autocomplete="off"
				bind:value={content}
				maxlength={data.options?.maxContentSize
					? Math.floor(data.options.maxContentSize / 4)
					: undefined}
			></textarea>
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
			{#if selectedVisibility === 2}
				<input
					type="password"
					placeholder="Password for private paste"
					class="mb-4 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
					spellcheck="false"
					autocomplete="off"
					bind:value={password}
				/>
			{/if}
			<button
				type="submit"
				class="w-full cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900"
				>Create Paste</button
			>
			{#if error}
				<div
					transition:fly={{ y: 40, duration: 300 }}
					class="rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200"
				>
					{error}
				</div>
			{/if}
		</form>
	</div>
</main>
