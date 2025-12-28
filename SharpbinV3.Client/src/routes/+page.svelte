<script lang="ts">
	import type { PageData } from './$types';
	import { displayNames } from '$lib/consts';

	export let data: PageData;

	let title = '';
	let content = '';
	let selectedSyntax = data.options.syntaxes[0];
	let selectedVisibility = data.options.visibilities[0].value;
	let password = '';

	async function handleSubmit(event: Event) {
		event.preventDefault();
		const params = new URLSearchParams({
			title: title.trim(),
			syntax: selectedSyntax,
			visibility: selectedVisibility.toString()
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
		const response = await fetch(url, options);
		if (response.ok) {
			const result = await response.json();
			window.location.href = `/${result.id}`;
		} else {
			alert('Failed to create paste. Please try again.');
		}
	}

	async function encryptAES(content: string, password: string): Promise<string> {
		const enc = new TextEncoder();
		const keyMaterial = await window.crypto.subtle.importKey(
			'raw',
			enc.encode(password),
			{ name: 'PBKDF2' },
			false,
			['deriveBits', 'deriveKey']
		);
		const salt = window.crypto.getRandomValues(new Uint8Array(16));
		const key = await window.crypto.subtle.deriveKey(
			{
				name: 'PBKDF2',
				salt: salt,
				iterations: 100000,
				hash: 'SHA-256'
			},
			keyMaterial,
			{ name: 'AES-GCM', length: 256 },
			false,
			['encrypt']
		);
		const iv = window.crypto.getRandomValues(new Uint8Array(12));
		const encryptedContent = await window.crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: iv
			},
			key,
			enc.encode(content)
		);
		const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength);
		combined.set(salt, 0);
		combined.set(iv, salt.byteLength);
		combined.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);
		const result = {
			version: 1,
			kdf: 'PBKDF2',
			iterations: 100000,
			hash: 'SHA-256',
			algorithm: 'AES-GCM',
			data: btoa(String.fromCharCode(...combined))
		};
		return JSON.stringify(result);
	}
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div class="rounded border-2 border-neutral-800 bg-neutral-900 p-6 w-full max-w-5xl">
		<h1 class="mb-6 text-center text-4xl font-bold">Create a Paste</h1>
		<form class="mt-4" on:submit|preventDefault={handleSubmit}>
			<input
				type="text"
				placeholder="Title (optional)"
				class="mb-4 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
				spellcheck="false"
				autocomplete="off"
				bind:value={title}
			/>
			<textarea
				placeholder="Your paste content here..."
				class="mb-4 h-64 max-h-[50vh] min-h-10 w-full resize-y rounded border border-neutral-700 bg-neutral-800 p-2"
				spellcheck="false"
				autocomplete="off"
				bind:value={content}
			></textarea>
			<select
				class="mb-4 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
				bind:value={selectedSyntax}
			>
				{#each data.options.syntaxes as lang (lang)}
					<option value={lang}
						>{displayNames[lang] ?? lang.charAt(0).toUpperCase() + lang.slice(1)}</option
					>
				{/each}
			</select>
			<select
				class="mb-4 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
				bind:value={selectedVisibility}
			>
				{#each data.options.visibilities as visibility (visibility.value)}
					<option value={visibility.value}>{visibility.displayName}</option>
				{/each}
			</select>
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
				class="w-full rounded bg-neutral-700 px-4 py-2 font-semibold text-white transition-colors duration-200 hover:bg-neutral-800 active:bg-neutral-900"
				>Create Paste</button
			>
		</form>
	</div>
</main>
