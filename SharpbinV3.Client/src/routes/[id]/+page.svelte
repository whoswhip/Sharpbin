<script lang="ts">
	import hljs from 'highlight.js';
	import { onMount } from 'svelte';
	import type { PageData } from './$types';
	import { FileBox, Eye, User, CalendarDays, CalendarOff, Code } from '@lucide/svelte/icons/index';
	import {
		formatBytes,
		extractDateFromUUIDv7,
		dateToRelativeString,
		tooltip
	} from '$lib/utils/misc';
	import { displayNames } from '$lib/consts';
	import { resolve } from '$app/paths';
	import { decryptAES } from '$lib/utils/encryption';
	export let data: PageData;

	let codeElement: HTMLElement;
	let showPasswordModal = false;
	let passwordInput = '';
	let decryptedContent: string | null = null;
	let decryptError = '';
	let contentRendered = false;

	function addLineNumbers(html: string): string {
		const match = html.match(/<pre.*?>[\s\S]*?<code.*?>([\s\S]*?)<\/code><\/pre>/);
		if (!match) return html;
		const code = match[1];
		const lines = code.split(/\n/);
		const digits = String(lines.length).length;
		const numbered = lines
			.map(
				(line, i) =>
					`<div class="code-row"><span class="line-number" style="width:${digits}ch">${i + 1}</span><span class="code-line">${line}</span></div>`
			)
			.join('');
		return html.replace(code, numbered);
	}

	function renderCode() {
		if (!codeElement || !data?.paste) return;
		let code = decryptedContent ?? data.content ?? '';
		if (data.paste.visibility === 2 && JSON.parse(data.content)?.kdf) {
			let json = JSON.parse(data.content);
			if (json?.version === 1) {
			}
		}
		const lang = (data.paste.syntax ?? '').toLowerCase();
		let highlighted = '';
		try {
			if (lang === 'plaintext') {
				const escapeHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
				highlighted = escapeHtml(code);
			} else if (lang && hljs.getLanguage && hljs.getLanguage(lang)) {
				highlighted = hljs.highlight(code, { language: lang, ignoreIllegals: true }).value;
			} else {
				highlighted = hljs.highlightAuto(code).value;
			}
		} catch {
			if (lang === 'plaintext') {
				const escapeHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
				highlighted = escapeHtml(code);
			} else {
				highlighted = hljs.highlightAuto(code).value;
			}
		}
		const wrapped = `<pre><code class="hljs">${highlighted}</code></pre>`;
		codeElement.innerHTML = addLineNumbers(wrapped);
		contentRendered = true;
	}

	onMount(async () => {
		try {
			if (data?.paste && data.paste.visibility === 2) {
				contentRendered = false;
				const urlHash = window.location.hash.slice(1);
				if (urlHash) {
					const passwordFromUrl = atob(urlHash);
					decryptedContent = await decryptAES(data.content, passwordFromUrl);
					if (decryptedContent === null) {
						showPasswordModal = true;
					} else {
						renderCode();
					}
					return;
				}
				showPasswordModal = true;
			} else {
				renderCode();
			}
		} catch {
			renderCode();
		}
	});

	$: if (data?.paste && (data.paste.visibility !== 2 || decryptedContent !== null)) renderCode();
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div
		class="max-h-[80vh] w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-4"
	>
		{#if data.paste}
			<h1
				class="mb-4 truncate text-center text-4xl font-bold"
				use:tooltip={data.paste.title && data.paste.title.length > 40 ? data.paste.title : ''}
			>
				{data.paste.title || 'Untitled Paste'}
			</h1>
			<div class="mb-2 flex flex-wrap items-center justify-center gap-4">
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<div class="relative flex shrink-0 items-center">
					<div class="flex" use:tooltip={`True Size: ${formatBytes(data.paste.trueSize)}`}>
						<FileBox class="mr-2 h-6 w-6 text-neutral-400" />
						<span class="text-neutral-400">{formatBytes(data.paste.size)}</span>
					</div>
				</div>

				<div class="flex shrink-0 items-center">
					<Eye class="mr-2 h-6 w-6 text-neutral-400" />
					<span class="text-neutral-400"
						>{data.paste.views} view{data.paste.views !== 1 ? 's' : ''}</span
					>
				</div>

				<div class="flex shrink-0 items-center">
					<CalendarDays class="mr-2 h-6 w-6 text-neutral-400" />
					<span
						class="text-neutral-400"
						use:tooltip={extractDateFromUUIDv7(data.paste.uuid)?.toLocaleString() ?? 'Unknown Date'}
					>
						{extractDateFromUUIDv7(data.paste.uuid)?.toLocaleDateString() ?? 'Unknown Date'}
					</span>
				</div>

				{#if data.paste.expiresAt !== 0}
					<div class="flex shrink-0 items-center">
						<CalendarOff class="mr-2 h-6 w-6 text-neutral-400" />
						<span class="text-neutral-400" title={new Date(data.paste.expiresAt).toLocaleString()}>
							Expires in {dateToRelativeString(new Date(data.paste.expiresAt), false)}
						</span>
					</div>
				{/if}

				<div class="flex shrink-0 items-center">
					<User class="mr-2 h-6 w-6 text-neutral-400" />
					{#if data.paste.author}
						<a
							href={resolve(`/user/${data.paste.author.username}`)}
							class="text-neutral-400 transition-colors duration-300 hover:text-neutral-500"
							>{data.paste.author.username}</a
						>
					{:else}
						<span class="text-neutral-400">Anonymous</span>
					{/if}
				</div>
				<div class="flex shrink-0 items-center">
					<Code class="mr-2 h-6 w-6 text-neutral-400" />
					<span class="text-neutral-400">
						{displayNames[data.paste.syntax] ??
							data.paste.syntax.charAt(0).toUpperCase() + data.paste.syntax.slice(1)}
					</span>
				</div>
			</div>
			<div class="h-15 w-full rounded bg-neutral-800" class:hidden={contentRendered}></div>
			<code
				class="codeblock-with-lines hidden max-w-full overflow-x-auto overflow-y-auto"
				style="max-width:100vw; min-width:0;"
				class:hidden={!contentRendered}
				bind:this={codeElement}
			>
			</code>
		{:else}
			<h1 class="mb-4 text-center text-4xl font-bold">Paste not found</h1>
			<h2 class="mt-2 text-center text-xl">The paste you are looking for does not exist.</h2>
		{/if}
	</div>

	{#if showPasswordModal}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<form
				on:submit|preventDefault={async () => {
					decryptError = '';
					try {
						const decrypted = await decryptAES(data.content ?? '', passwordInput);
						if (decrypted === null) {
							decryptError = 'Incorrect password. Please try again.';
						} else {
							decryptedContent = decrypted;
							showPasswordModal = false;
							renderCode();
							history.replaceState(null, '', window.location.pathname + window.location.search);
						}
					} catch {
						decryptError = 'An error occurred during decryption. Please try again.';
					}
				}}
				class="w-full max-w-md rounded bg-neutral-900 p-6"
			>
				<h2 class="mb-4 text-xl font-semibold">Enter password to decrypt</h2>
				<input
					type="text"
					bind:value={passwordInput}
					class="mb-3 w-full rounded border border-neutral-700 bg-neutral-800 p-2"
				/>
				{#if decryptError}
					<div class="mb-3 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
						{decryptError}
					</div>
				{/if}
				<div class="flex gap-2">
					<button
						type="submit"
						class="flex-1 cursor-pointer rounded bg-neutral-700 px-4 py-2 font-semibold text-white hover:bg-neutral-800"
						>Decrypt</button
					>
					<button
						type="button"
						on:click={() => {
							showPasswordModal = false;
							decryptError = '';
						}}
						class="cursor-pointer rounded border border-neutral-700 px-4 py-2 hover:bg-neutral-950"
						>Cancel</button
					>
				</div>
			</form>
		</div>
	{/if}

	<style>
		.hljs {
			background-color: var(--color-neutral-800) !important;
		}
		.codeblock-with-lines {
			display: block;
			width: 100%;
			max-width: 100%;
			overflow: visible;
		}
		.codeblock-with-lines pre {
			display: block;
			position: relative;
			margin: 0;
			background: none;
			border-radius: 0.25em;
			background-color: var(--color-neutral-800) !important;
			overflow: auto;
			box-sizing: border-box;
			min-width: 0;
			width: 100%;
			max-height: 60vh;
		}
		.code-row {
			display: flex;
			align-items: flex-start;
			min-width: 0;
			padding: 0.1em 0;
			border-radius: 0.15em;
		}
		.code-row:hover {
			background-color: rgba(255, 255, 255, 0.05);
		}
		.line-number {
			flex-shrink: 0;
			text-align: right;
			color: #888;
			user-select: none;
			margin-right: 1em;
			font-variant-numeric: tabular-nums;
			padding-right: 0.5em;
			padding-left: 0.25em;
			background: none;
		}
		.code-line {
			display: block;
			white-space: pre-wrap;
			word-break: break-word;
			overflow-wrap: anywhere;
			padding-left: 0.25em;
			min-width: 0;
		}
	</style>
</main>
