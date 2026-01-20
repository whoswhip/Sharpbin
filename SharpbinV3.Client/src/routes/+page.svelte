<script lang="ts">
	import type { PageData } from './$types';
	import { syntaxes } from '$lib/consts';
	import { user } from '$lib/stores/user';
	import { getToken } from '$lib/utils/auth';
	import { onMount } from 'svelte';
	import { fly, fade } from 'svelte/transition';
	import { encryptAES, estimateEncryptedSize } from '$lib/utils/encryption';
	import {
		formatBytes,
		formatNumber,
		isBinaryData,
		tooltip,
		syntaxFromExtension
	} from '$lib/utils/misc';
	import Dropdown from '$lib/components/Dropdown.svelte';
	import { SvelteURLSearchParams } from 'svelte/reactivity';
	import { FileUp, X, Eye, EyeClosed, Dices } from '@lucide/svelte';

	export let data: PageData;

	let textArea: HTMLTextAreaElement;

	let error = '';
	let title = '';
	let content = '';
	let selectedSyntax = data.options?.syntaxes?.[0];
	let expiresIn: number = 0;
	let selectedVisibility = data.options?.visibilities?.[0]?.value;
	let password = '';
	let passwordVisible = false;
	let anonymousUpload = false;
	let isDragging = false;
	let dragError = '';

	$: currentByteSize =
		selectedVisibility === 2
			? estimateEncryptedSize(content)
			: new TextEncoder().encode(content).length;

	const MAX_HEIGHT = () => Math.floor((window.innerHeight - 120) * 0.6);

	function resize() {
		if (!textArea) return;

		textArea.style.height = 'auto';

		const h = textArea.scrollHeight;
		const max = MAX_HEIGHT();

		if (h > max) {
			textArea.style.height = max + 'px';
			textArea.style.overflowY = 'auto';
		} else {
			textArea.style.height = h + 'px';
			textArea.style.overflowY = 'hidden';
		}
	}

	onMount(() => {
		resize();
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
			label: syntaxes[lang]?.name ?? lang.charAt(0).toUpperCase() + lang.slice(1)
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

		if (content.trim().length === 0) {
			error = 'Paste content cannot be empty.';
			setTimeout(() => {
				error = '';
			}, 5000);
			return;
		}

		let body = content;
		if (selectedVisibility === 2) {
			body = await encryptAES(content, password);
		}

		if (
			data.options?.maxPasteSize &&
			new TextEncoder().encode(body).length > data.options.maxPasteSize
		) {
			error = `Paste exceeds the maximum size limit of ${formatBytes(data.options.maxPasteSize)}. ${selectedVisibility === 2 ? 'Encryption adds some overhead.' : ''}`;
			setTimeout(() => {
				error = '';
			}, 5000);
			return;
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
			setTimeout(() => {
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
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
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
			<div>
				<div class="relative">
					<textarea
						placeholder="Your paste content here..."
						class="min-h-20 w-full resize-none overflow-hidden rounded rounded-b-none border border-neutral-700 bg-neutral-800 p-2 transition-colors duration-200"
						spellcheck="false"
						autocomplete="off"
						minlength="1"
						bind:this={textArea}
						bind:value={content}
						on:input={resize}
						on:change={resize}
						on:focus={resize}
						on:beforeinput={(e) => {
							if (!data.options?.maxPasteSize) return;

							const futureSize =
								selectedVisibility === 2
									? estimateEncryptedSize(content + (e.data ?? ''))
									: new TextEncoder().encode(content + (e.data ?? '')).length;

							if (futureSize > data.options.maxPasteSize) {
								e.preventDefault();
							}
						}}
						on:dragenter={(e) => {
							e.preventDefault();
							isDragging = true;
						}}
						on:dragover={(e) => {
							e.preventDefault();
							isDragging = true;
						}}
						on:dragleave={(e) => {
							e.preventDefault();
							isDragging = false;
						}}
						on:drop={(e) => {
							requestAnimationFrame(resize);
							e.preventDefault();
							isDragging = false;

							const file = e.dataTransfer?.files[0];
							if (!file) return;

							const reader = new FileReader();

							reader.onload = (e) => {
								const arrayBuffer = e.target?.result as ArrayBuffer;
								if (isBinaryData(new Uint8Array(arrayBuffer))) {
									content = '';
									dragError = 'The dropped file appears to be binary and cannot be pasted as text.';
									setTimeout(() => {
										dragError = '';
									}, 5000);
									return;
								}
								const syntax = syntaxFromExtension(file.name.split('.').pop() || '');
								if (syntax && selectedSyntax !== syntax) {
									selectedSyntax = syntax;
								} else if (!syntax && selectedSyntax !== 'plaintext') {
									selectedSyntax = 'plaintext';
								}
								title = file.name;
								const decoder = new TextDecoder();
								content = decoder.decode(arrayBuffer);
							};

							reader.readAsArrayBuffer(file);
						}}
					></textarea>
					{#if isDragging || (dragError && dragError !== '')}
						<div
							class="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-md rounded-b-none border-2 border-dashed border-neutral-500 bg-neutral-800/70 text-center text-neutral-300"
							transition:fade={{ duration: 150 }}
						>
							<div class="relative flex h-full w-full items-center justify-center">
								{#if dragError && dragError !== ''}
									<div
										class="absolute flex flex-col items-center gap-4"
										transition:fly={{ y: -20, duration: 200 }}
									>
										<X class="h-12 w-12 text-red-500" />
										<p>{dragError}</p>
									</div>
								{:else}
									<div
										class="absolute flex flex-col items-center gap-4"
										transition:fly={{ y: -20, duration: 200 }}
									>
										<FileUp class="h-12 w-12" />
									</div>
								{/if}
							</div>
						</div>
					{/if}
				</div>
				<div
					class="monospace mb-2 flex h-12 items-center justify-between rounded-b border border-neutral-700 bg-neutral-800 p-1 pr-2 pl-2 text-sm text-neutral-400 md:h-8"
				>
					<div class="flex flex-col md:flex-row md:gap-2">
						<span>
							{content.split('\n').length} line{content.split('\n').length !== 1 ? 's' : ''}
						</span>
						<span class="hidden text-neutral-600 md:block">•</span>
						<span>{formatNumber(content.length)} char{content.length !== 1 ? 's' : ''}</span>
					</div>
					<div class="flex flex-col text-center md:flex-row md:gap-2">
						<span
							class="border-b border-neutral-600 md:border-0"
							class:text-red-500={currentByteSize > (data.options?.maxPasteSize ?? 0)}
						>
							{formatBytes(currentByteSize)}
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
				<div class="flex w-full">
					<input
						type={passwordVisible ? 'text' : 'password'}
						placeholder="Password for private paste"
						class="w-[calc(100%-100px)] rounded-l border border-neutral-700 bg-neutral-800 p-2"
						spellcheck="false"
						autocomplete="off"
						minlength="6"
						bind:value={password}
					/>
					<button
						type="button"
						class="mr-1 ml-1 flex w-12.5 items-center justify-center border border-neutral-700 bg-neutral-800 p-2 text-neutral-400 hover:bg-neutral-700"
						on:click={() => {
							const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
							const bytes = new Uint8Array(16);
							crypto.getRandomValues(bytes);
							password = Array.from(bytes, (b) => chars[b % chars.length]).join('');
						}}
						use:tooltip={'Generate Random Password'}
					>
						<Dices class="h-5 w-5" />
					</button>
					<button
						type="button"
						class="flex w-12.5 items-center justify-center rounded-r border border-neutral-700 bg-neutral-800 p-2 text-neutral-400 hover:bg-neutral-700"
						on:click={() => (passwordVisible = !passwordVisible)}
					>
						{#if passwordVisible}
							<EyeClosed class="h-5 w-5" />
						{:else}
							<Eye class="h-5 w-5" />
						{/if}
					</button>
				</div>
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
					class="mt-2 flex min-h-16.25 w-auto items-center justify-center rounded border border-neutral-700 bg-neutral-800 p-2 pb-1"
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
