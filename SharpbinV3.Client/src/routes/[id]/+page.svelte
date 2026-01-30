<script lang="ts">
	import hljs from 'highlight.js';
	import Papa from 'papaparse';
	import { onMount } from 'svelte';
	import type { PageData } from './$types';
	import {
		File,
		FileBox,
		Eye,
		Globe,
		Lock,
		EyeOff,
		User,
		CalendarDays,
		CalendarOff,
		Code,
		Pencil,
		PencilOff,
		PencilLine,
		Trash2,
		Download,
		Copy,
		Check,
		CalendarCog,
		Flag,
		ArrowUp
	} from '@lucide/svelte/icons/index';
	import {
		formatBytes,
		formatNumber,
		extractDateFromUUIDv7,
		dateToRelativeString,
		tooltip,
		isBinaryData
	} from '$lib/utils/misc';
	import { parseMarkdown } from '$lib/utils/markdown';
	import { syntaxes, expiresOptions } from '$lib/consts';
	import { resolve } from '$app/paths';
	import { decryptAES, encryptAES } from '$lib/utils/encryption';
	import { fade } from 'svelte/transition';
	import { getToken } from '$lib/utils/auth';
	import { user } from '$lib/stores/user';
	import Dropdown from '$lib/components/Dropdown.svelte';
	import { openModal } from '$lib/stores/modal';
	import type { Paste } from '$lib/types/paste';
	export let data: PageData;

	let reportSiteKey: string | null = null;
	let editing = false;
	let editContent: string | null = null;
	let editMetadata: Paste | null = data.paste ? { ...data.paste } : null;
	let editError = '';
	let editLoading = false;
	let isBinary = false;
	let pasteContent = '';
	let decryptedContent: string | null = null;
	let decryptError = '';
	let decryptStatus = '';
	let contentRendered = false;
	let downloadedPaste = false;
	let copiedPaste = false;

	let scrollY = 0;

	let now = new Date();
	$: isExpired =
		data?.paste?.expiresAt && data.paste.expiresAt !== 0
			? new Date(data.paste.expiresAt).getTime() <= now.getTime()
			: false;

	let interval: ReturnType<typeof setInterval> | null = null;

	const syntaxOptions =
		data.options?.syntaxes?.map((lang: string) => ({
			value: lang,
			label: syntaxes[lang]?.name ?? lang.charAt(0).toUpperCase() + lang.slice(1)
		})) ?? [];

	const visibilityOptions =
		data.options?.visibilities?.map((visibility: { value: number; displayName: string }) => ({
			value: visibility.value,
			label: visibility.displayName
		})) ?? [];

	const modalTitleMap = {
		decrypt: 'Decrypt Paste',
		encrypt: 'Encrypt Paste',
		confirm: 'Are you sure you want to delete this paste?',
		report: 'Report Paste'
	};

	onMount(() => {
		interval = setInterval(() => {
			now = new Date();
		}, 1000);
		return () => {
			if (interval) clearInterval(interval);
		};
	});

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

	async function renderPaste(content: string | null = null) {
		if (!data?.paste) return;

		let contentToRender = content ?? decryptedContent ?? data.content ?? '';

		isBinary = isBinaryData(new TextEncoder().encode(contentToRender).buffer);
		if (isBinary) {
			contentRendered = true;
			decryptStatus = '';
			return;
		}

		switch (data.paste.syntax) {
			case 'markdown':
				pasteContent = await parseMarkdown(contentToRender);
				contentRendered = true;
				decryptStatus = '';
				break;
			case 'csv':
				await renderCsv(contentToRender);
				break;
			default:
				await renderCode(contentToRender);
				break;
		}
	}

	async function renderCode(content: string | null = null) {
		if (!data?.paste) return;
		let code = content ?? decryptedContent ?? data.content ?? '';

		const lang = (data.paste.syntax ?? '').toLowerCase();

		let highlighted = '';
		try {
			if (lang === 'plaintext') {
				const escapeHtml = (s: string) =>
					s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
				highlighted = escapeHtml(code);
			} else if (lang && hljs.getLanguage && hljs.getLanguage(lang)) {
				highlighted = hljs.highlight(code, { language: lang, ignoreIllegals: true }).value;
			} else {
				highlighted = hljs.highlightAuto(code).value;
			}
		} catch {
			if (lang === 'plaintext') {
				const escapeHtml = (s: string) =>
					s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
				highlighted = escapeHtml(code);
			} else {
				highlighted = hljs.highlightAuto(code).value;
			}
		}
		const wrapped = `<pre><code class="hljs">${highlighted}</code></pre>`;
		pasteContent = addLineNumbers(wrapped);
		contentRendered = true;
		decryptStatus = '';
	}

	async function renderCsv(content: string) {
		try {
			const results = Papa.parse(content, {
				header: false,
				skipEmptyLines: true,
				dynamicTyping: false
			});

			if (!results.data || results.data.length === 0) {
				pasteContent = '<div class="p-4 text-neutral-400">No data in CSV</div>';
				contentRendered = true;
				decryptStatus = '';
				return;
			}

			const rows = results.data as string[][];
			const [header, ...body] = rows;

			const escape = (v: string) =>
				v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

			const tableHtml = `
			<table class="csv-table">
				<thead>
					<tr>
						${header.map((c) => `<th>${c ? escape(c) : ''}</th>`).join('')}
					</tr>
				</thead>
				<tbody>
					${body
						.map((row) => `<tr>${row.map((c) => `<td>${c ? escape(c) : ''}</td>`).join('')}</tr>`)
						.join('')}
				</tbody>
			</table>
		`;

			pasteContent = tableHtml;
			contentRendered = true;
			decryptStatus = '';
		} catch {
			pasteContent = '<div class="p-4 text-red-400">Failed to parse CSV</div>';
			contentRendered = true;
			decryptStatus = '';
		}
	}

	async function updatePaste(content: string | null, metadata: Paste | null) {
		editError = '';
		editLoading = true;
		try {
			if (!data?.paste) {
				editError = 'Paste data is missing.';
				editLoading = false;
				return;
			}
			const token = getToken();
			if (!token) {
				editError = 'Not authenticated.';
				editLoading = false;
				return;
			}
			if (
				(content !== (decryptedContent ?? data.content) ||
					metadata?.visibility === 2 ||
					data.paste.visibility === 2) &&
				content !== null
			) {
				let rawContent = content;
				if (metadata?.visibility === 2 || data.paste.visibility === 2) {
					const password = await promptUser('encrypt');
					if (!password) {
						editError = 'Password required for encryption.';
						editLoading = false;
						return;
					}
					const encrypted = await encryptAES(content, password);
					content = encrypted;
				}
				const res = await fetch(`/api/paste/${data.paste.id}`, {
					method: 'PUT',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${token}`
					},
					body: content
				});
				if (!res.ok) {
					const err = await res.json().catch(() => ({}));
					editError = err?.message || 'Failed to update paste content.';
					editLoading = false;
					return;
				}
				data.content = rawContent;
				decryptedContent = rawContent;
				await renderPaste(rawContent);
			}
			if (
				(metadata?.syntax !== data.paste.syntax ||
					metadata?.expiresAt !== data.paste.expiresAt ||
					metadata?.visibility !== data.paste.visibility ||
					metadata?.title !== data.paste.title) &&
				metadata !== null
			) {
				const res = await fetch(`/api/paste/${data.paste.id}`, {
					method: 'PATCH',
					headers: {
						'Content-Type': 'application/json',
						Authorization: `Bearer ${token}`
					},
					body: JSON.stringify({
						syntax: metadata.syntax,
						expiresAt: metadata.expiresAt === 0 ? 0 : Date.now() + (metadata.expiresAt ?? 0),
						visibility: metadata.visibility,
						title: metadata.title
					})
				});
				if (!res.ok) {
					const err = await res.json().catch(() => ({}));
					editError = err?.message || 'Failed to update paste metadata.';
					editLoading = false;
					return;
				}
				const resJson = await res.json();
				data.paste.syntax = resJson.paste.syntax ?? data.paste.syntax;
				data.paste.expiresAt = resJson.paste.expiresAt ?? data.paste.expiresAt;
				data.paste.visibility = resJson.paste.visibility ?? data.paste.visibility;
				data.paste.title = resJson.paste.title ?? data.paste.title;
			}
		} catch {
			editError = 'An error occurred while updating.';
		} finally {
			editLoading = false;
			editing = false;
			editContent = null;
		}
	}

	async function promptUser(mode: 'decrypt' | 'encrypt' | 'confirm' | 'report' = 'decrypt') {
		const title = modalTitleMap[mode];
		if (mode === 'confirm') {
			const ok = await openModal<boolean>({ mode, title, cancelValue: false });
			return ok ? 'true' : '';
		}
		if (mode === 'report') {
			await openModal({
				mode,
				title,
				reportTarget: 'paste',
				reportTargetId: data.paste?.id ?? null,
				reportSiteKey,
				cancelValue: ''
			});
			return '';
		}
		const value = await openModal<string>({ mode, title, error: decryptError, cancelValue: '' });
		decryptError = '';
		return value;
	}

	function handleMarkdownClick(event: MouseEvent) {
		const target = event.target as HTMLElement;
		const placeholder = target.closest('.media-placeholder') as HTMLElement;
		if (placeholder) {
			event.preventDefault();
			event.stopPropagation();

			if (target.classList.contains('load-media-btn')) {
				const src = target.getAttribute('data-src');
				const tag = target.getAttribute('data-tag');
				if (!src || !tag) return;

				const element = document.createElement(tag);

				if (tag === 'img') {
					element.setAttribute('alt', target.getAttribute('data-alt') || '');
					element.setAttribute('style', 'max-width:100%; height:auto; border-radius:0.375rem;');
					element.onload = () => {
						const href = target.getAttribute('data-href');
						if (href) {
							const anchor = document.createElement('a');
							anchor.setAttribute('href', href);
							const targetAttr = target.getAttribute('data-target');
							if (targetAttr) anchor.setAttribute('target', targetAttr);
							anchor.appendChild(element);
							placeholder.replaceWith(anchor);
						} else {
							placeholder.replaceWith(element);
						}
					};
					element.onerror = () => {
						target.textContent = 'Error loading image';
						target.style.backgroundColor = '#7f1d1d';
						target.style.opacity = '1';
					};
				} else {
					if (tag === 'video' || tag === 'audio') {
						element.setAttribute('controls', '');
						element.setAttribute('style', 'max-width:100%;');
					} else if (tag === 'iframe') {
						element.setAttribute('style', 'width:100%; min-height:400px; border:none;');
					}

					const href = target.getAttribute('data-href');
					if (href) {
						const anchor = document.createElement('a');
						anchor.setAttribute('href', href);
						const targetAttr = target.getAttribute('data-target');
						if (targetAttr) anchor.setAttribute('target', targetAttr);
						anchor.appendChild(element);
						placeholder.replaceWith(anchor);
					} else {
						placeholder.replaceWith(element);
					}
				}

				['width', 'height', 'title'].forEach((attr) => {
					const val = target.getAttribute(`data-${attr}`);
					if (val) element.setAttribute(attr, val);
				});

				target.textContent = 'Loading...';
				target.style.opacity = '0.5';
				target.style.cursor = 'wait';

				element.setAttribute('src', src);
			}
		}
	}

	onMount(async () => {
		try {
			if (data?.paste && data.paste.visibility === 2) {
				contentRendered = false;
				decryptStatus = 'Preparing decryption...';
				const urlHash = window.location.hash.slice(1);
				if (urlHash) {
					const passwordFromUrl = atob(urlHash);
					decryptStatus = 'Deriving key...';
					decryptedContent = await decryptAES(data.content, passwordFromUrl);
					if (decryptedContent === null) {
						decryptStatus = 'Waiting for password...';
						const password = await promptUser('decrypt');
						if (password) {
							decryptStatus = 'Deriving key...';
							decryptedContent = await decryptAES(data.content, password);
							if (decryptedContent === null) {
								decryptError = 'Incorrect password. Please try again.';
								decryptStatus = 'Decryption failed.';
							} else {
								await renderPaste();
								history.replaceState(null, '', window.location.pathname + window.location.search);
							}
						} else {
							decryptStatus = 'Decryption canceled.';
						}
					} else {
						await renderPaste();
					}
					return;
				}
				decryptStatus = 'Waiting for password...';
				const password = await promptUser('decrypt');
				if (password) {
					decryptStatus = 'Deriving key...';
					decryptedContent = await decryptAES(data.content, password);
					if (decryptedContent === null) {
						decryptError = 'Incorrect password. Please try again.';
						decryptStatus = 'Decryption failed.';
					} else {
						await renderPaste();
					}
				} else {
					decryptStatus = 'Decryption canceled.';
				}
			} else {
				decryptStatus = 'Rendering content...';
				await renderPaste();
			}
		} catch {
			decryptStatus = 'Rendering content...';
			await renderPaste();
		}
	});

	$: if (data?.paste && (data.paste.visibility !== 2 || decryptedContent !== null)) renderPaste();
	$: reportSiteKey =
		(data as unknown as { authOptions?: { cf_turnstile_site_key?: string | null } }).authOptions
			?.cf_turnstile_site_key ?? null;
</script>

<svelte:window bind:scrollY />

<svelte:head>
	<title
		>{data.paste
			? (data.paste.title || 'Untitled Paste') + ' - Sharpbin'
			: 'Paste Not Found - Sharpbin'}</title
	>
	{#if data.paste}
		<meta property="og:title" content={data.paste.title || 'Untitled Paste'} />
		<meta
			property="og:description"
			content={`A ${syntaxes[data.paste.syntax].name} paste on Sharpbin created by ${
				data.paste.author ? data.paste.author.username : 'Anonymous'
			}, created on ${
				extractDateFromUUIDv7(data.paste.uuid)?.toLocaleDateString() ?? 'Unknown Date'
			} with ${data.paste.views} view${data.paste.views !== 1 ? 's' : ''}.`}
		/>
		<meta property="og:type" content="article" />
		<meta property="og:url" content={data.url} />
		<meta property="og:site_name" content="Sharpbin" />
		<meta
			property="og:article:published_time"
			content={extractDateFromUUIDv7(data.paste.uuid)?.toISOString() ?? ''}
		/>
		{#if data.paste.editedAt}
			<meta
				property="og:article:modified_time"
				content={new Date(data.paste.editedAt).toISOString()}
			/>
		{/if}
		{#if data.paste.author}
			<meta property="og:article:author" content={data.paste.author.username} />
		{/if}
	{/if}
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-4">
		{#if data.paste}
			<div class="mb-4 w-full text-center">
				<h1
					class="mx-auto max-w-[90%] min-w-0 truncate text-3xl leading-tight font-bold sm:text-4xl"
					use:tooltip={data.paste.title && data.paste.title.length > 40 ? data.paste.title : ''}
				>
					{#if !editing}
						{data.paste.title || 'Untitled Paste'}
					{:else if editMetadata}
						<input
							type="text"
							bind:value={editMetadata.title}
							class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
							placeholder="Untitled Paste"
							maxlength={data.options?.maxTitleLength ?? 500}
						/>
					{/if}
				</h1>
				<div class="flex items-center justify-center gap-2 text-sm text-neutral-400">
					<User class="inline-block h-4 w-4 text-neutral-400" />
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
			</div>
			<div class="mb-2">
				<div class="flex flex-wrap items-center justify-center gap-4">
					<div class="relative flex shrink-0 items-center">
						<div
							class="flex"
							use:tooltip={`${
								data.paste.isCompressed ? `Compressed Size: ${formatBytes(data.paste.size)}` : ''
							}${
								data.paste.visibility === 2
									? ` • Decrypted Size: ${formatBytes(decryptedContent ? new TextEncoder().encode(decryptedContent).length : 0)}`
									: ''
							}`}
						>
							<FileBox class="mr-2 h-6 w-6 text-neutral-400" />
							<span class="text-neutral-400">{formatBytes(data.paste.trueSize)}</span>
						</div>
					</div>

					<div class="flex shrink-0 items-center">
						<Eye class="mr-2 h-6 w-6 text-neutral-400" />
						<span class="text-neutral-400"
							>{data.paste.views} view{data.paste.views !== 1 ? 's' : ''}</span
						>
					</div>

					{#if data.paste.reportCount !== null && data.paste.reportCount > 0}
						<div class="flex shrink-0 items-center">
							<Flag class="mr-2 h-6 w-6 text-neutral-400" />
							<a
								class="text-neutral-400 hover:text-neutral-200 hover:underline"
								href={resolve(`/reports?target=pastes&pasteId=${data.paste.id}`)}
								>{data.paste.reportCount} report{data.paste.reportCount !== 1 ? 's' : ''}</a
							>
						</div>
					{/if}

					<div class="flex shrink-0 items-center">
						<CalendarDays class="mr-2 h-6 w-6 text-neutral-400" />
						<span
							class="text-neutral-400"
							use:tooltip={`Created on ${
								extractDateFromUUIDv7(data.paste.uuid)?.toLocaleString() ?? 'Unknown Date'
							} • ${dateToRelativeString(extractDateFromUUIDv7(data.paste.uuid) ?? new Date(), true, true, now, 3)}`}
						>
							{extractDateFromUUIDv7(data.paste.uuid)?.toLocaleDateString() ?? 'Unknown Date'}
						</span>
					</div>
					{#if data.paste.editedAt}
						<div class="flex shrink-0 items-center">
							<CalendarCog class="mr-2 h-6 w-6 text-neutral-400" />
							<span
								class="text-neutral-400"
								use:tooltip={`Edited on ${new Date(data.paste.editedAt).toLocaleString()} • ${dateToRelativeString(new Date(data.paste.editedAt), true, true, now, 3)}`}
							>
								{#if new Date(data.paste.editedAt).getTime() > new Date().getTime() - 86400000}
									Edited {dateToRelativeString(new Date(data.paste.editedAt), false, false, now)} ago
								{:else}
									{new Date(data.paste.editedAt).toLocaleDateString()}
								{/if}
							</span>
						</div>
					{/if}
					{#if data.paste.expiresAt !== 0 || editing}
						<div class="flex shrink-0 items-center">
							<CalendarOff class="mr-2 h-6 w-6 text-neutral-400" />
							{#if !editing}
								<span
									class="text-neutral-400"
									use:tooltip={`Expires on ${new Date(data.paste.expiresAt).toLocaleString()} • ${dateToRelativeString(new Date(data.paste.expiresAt), true, true, now, 3)}`}
								>
									{isExpired ? 'Expired' : 'Expires in'}
									{dateToRelativeString(new Date(data.paste.expiresAt), false, false, now)}
									{isExpired ? 'ago' : ''}
								</span>
							{:else if editMetadata}
								<Dropdown
									options={expiresOptions}
									bind:value={editMetadata.expiresAt}
									placeholder="Select expiration..."
									variant="sm"
									displayValue={(val) => {
										const option = expiresOptions.find((opt) => opt.value === val);
										return option ? option.label : 'Select expiration...';
									}}
								/>
							{/if}
						</div>
					{/if}

					<div class="flex shrink-0 items-center">
						<Code class="mr-2 h-6 w-6 text-neutral-400" />
						{#if !editing}
							<span class="text-neutral-400">
								{syntaxes[data.paste.syntax]?.name ??
									data.paste.syntax.charAt(0).toUpperCase() + data.paste.syntax.slice(1)}
							</span>
						{:else if editMetadata && syntaxOptions}
							<Dropdown
								options={syntaxOptions}
								bind:value={editMetadata.syntax}
								placeholder="Select syntax..."
								searchable={true}
								variant="sm"
							/>
						{/if}
					</div>
					<div>
						<div class="flex shrink-0 items-center">
							{#if data.paste.visibility === 0}
								<Globe class="mr-2 h-6 w-6 text-neutral-400" />
								<span class="text-neutral-400">{editing ? '' : 'Public'}</span>
							{:else if data.paste.visibility === 1}
								<EyeOff class="mr-2 h-6 w-6 text-neutral-400" />
								<span class="text-neutral-400">{editing ? '' : 'Unlisted'}</span>
							{:else if data.paste.visibility === 2}
								<Lock class="mr-2 h-6 w-6 text-neutral-400" />
								<span class="text-neutral-400">{editing ? '' : 'Private'}</span>
							{/if}
							{#if editing && editMetadata}
								<Dropdown
									options={visibilityOptions}
									bind:value={editMetadata.visibility}
									placeholder="Select visibility..."
									variant="sm"
								/>
							{/if}
						</div>
					</div>
				</div>
			</div>
			<div
				class="sticky top-0 z-10 flex flex-col items-center justify-between gap-2 rounded-t-md border-b border-neutral-700 bg-neutral-800 px-3 py-2 md:flex-row"
			>
				{#if !isBinary}
					<div class="flex items-center gap-2 text-sm text-neutral-300">
						<span class="font-medium text-neutral-100"
							>{formatNumber((editContent ?? decryptedContent ?? data.content).length)}</span
						>
						<span class="text-neutral-400">chars</span>
						<span class="text-neutral-600">•</span>
						<span class="font-medium text-neutral-100"
							>{formatNumber(
								(editing ? (editContent ?? '') : (decryptedContent ?? data.content)).split('\n')
									.length
							)}</span
						>
						<span class="text-neutral-400"
							>line{(editing ? (editContent ?? '') : (decryptedContent ?? data.content)).split('\n')
								.length !== 1
								? 's'
								: ''}</span
						>
					</div>
				{:else}
					<div></div>
				{/if}
				<div class="flex shrink-0 flex-wrap items-center gap-2 sm:flex-nowrap">
					{#if !isBinary}
						<button
							type="button"
							class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
							on:click={() => {
								navigator.clipboard.writeText(decryptedContent ?? data.content);
								copiedPaste = true;
								setTimeout(() => (copiedPaste = false), 1000);
							}}
						>
							<div class="relative mr-1 h-5 w-5">
								{#if copiedPaste}
									<span
										transition:fade={{ duration: 200 }}
										class="absolute inset-0 flex items-center justify-center"
										><Check class="h-5 w-5 text-green-400" /></span
									>
								{:else}
									<span
										transition:fade={{ duration: 200 }}
										class="absolute inset-0 flex items-center justify-center"
										><Copy class="h-5 w-5 text-neutral-400" /></span
									>
								{/if}
							</div>

							<span class="text-neutral-300">Copy</span>
						</button>
					{/if}
					<button
						type="button"
						class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
						on:click={() => {
							const blob = new Blob([decryptedContent ?? data.content], {
								type: 'text/plain'
							});

							const syntax = syntaxes[data.paste?.syntax ?? 'plaintext'];
							let extension = '.txt';

							if (syntax && syntax.extension) {
								if (data.paste?.title?.endsWith(syntax.extension)) {
									extension = '';
								} else {
									extension = syntax.extension;
								}
							}

							const url = URL.createObjectURL(blob);
							const a = document.createElement('a');
							a.href = url;
							a.download = data.paste?.title
								? data.paste.title.slice(0, 100) + extension
								: `paste_${data.paste?.id}${extension}`;
							document.body.appendChild(a);
							a.click();
							document.body.removeChild(a);
							URL.revokeObjectURL(url);
							downloadedPaste = true;
							setTimeout(() => (downloadedPaste = false), 1000);
						}}
					>
						<div class="relative mr-1 h-5 w-5">
							{#if downloadedPaste}
								<span
									transition:fade={{ duration: 200 }}
									class="absolute inset-0 flex items-center justify-center"
									><Check class="h-5 w-5 text-green-400" /></span
								>
							{:else}
								<span
									transition:fade={{ duration: 200 }}
									class="absolute inset-0 flex items-center justify-center"
									><Download class="h-5 w-5 text-neutral-400" /></span
								>
							{/if}
						</div>

						<span class="text-neutral-300">Download</span>
					</button>

					<a
						href={resolve(`/raw/${data.paste.id}`)}
						class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
					>
						<File class="mr-1 h-5 w-5 text-neutral-400" />
						<span class="text-neutral-300">View Raw</span>
					</a>

					{#if $user !== null && $user.uuid !== data.paste?.author?.uuid}
						<button
							type="button"
							class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-amber-600/50"
							on:click={() => {
								promptUser('report');
							}}
						>
							<Flag class="mr-1 h-5 w-5 text-amber-400" />
							<span class="text-amber-300">Report</span>
						</button>
					{/if}
					{#if $user && ($user.uuid === data.paste?.author?.uuid || $user.roles.some((r) => r === 1 || r === 255))}
						{#if !editing}
							{#if !isBinary}
								<button
									type="button"
									class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
									on:click={() => {
										editContent = decryptedContent ?? data.content;
										editError = '';
										editing = true;
									}}
								>
									<Pencil class="mr-1 h-5 w-5 text-neutral-400" />
									<span class="text-neutral-300">Edit</span>
								</button>
							{/if}
							<button
								type="button"
								class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-red-900"
								on:click={() => {
									promptUser('confirm').then(async (value) => {
										if (value) {
											const token = getToken();
											if (!token) {
												return;
											}
											const res = await fetch(`/api/paste/${data.paste?.id}`, {
												method: 'DELETE',
												headers: {
													Authorization: `Bearer ${token}`
												}
											});
											if (res.ok) {
												window.location.href = resolve('/');
											} else {
												alert('Failed to delete paste.');
											}
										}
									});
								}}
							>
								<Trash2 class="mr-1 h-5 w-5 text-red-400" />
								<span class="text-red-300">Delete</span>
							</button>
						{:else}
							<button
								type="button"
								class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
								on:click={async () => {
									if (editContent !== null || editMetadata !== null) {
										await updatePaste(editContent, editMetadata);
									}
								}}
								disabled={editLoading}
							>
								<PencilLine class="mr-1 h-5 w-5 text-neutral-400" />
								<span class="text-neutral-300">{editLoading ? 'Saving...' : 'Save Edits'}</span>
							</button>
							<button
								type="button"
								class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
								on:click={() => {
									editing = false;
									editError = '';
								}}
							>
								<PencilOff class="mr-1 h-5 w-5 text-neutral-400" />
								<span class="text-neutral-300">Cancel Edit</span>
							</button>
						{/if}
					{/if}
					{#if scrollY > 400 && contentRendered && !editing}
						<button
							transition:fade={{ duration: 200 }}
							class="flex cursor-pointer items-center rounded-md bg-neutral-700 px-2 py-0.5 text-sm hover:bg-neutral-600"
							on:click={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
							aria-label="Scroll to top"
						>
							<ArrowUp class="mr-1 h-5 w-5 text-neutral-400" />
							<span class="text-neutral-300">Scroll to top</span>
						</button>
					{/if}
				</div>
			</div>
			{#if isBinary}
				<div
					class="flex h-16 w-full flex-col items-center justify-center rounded-b bg-neutral-800 p-4 text-neutral-400"
				>
					<p>We cannot display this paste because it is not text</p>
				</div>
			{:else if editing}
				<textarea
					class="mb-3 max-h-[40vh] min-h-10 w-full rounded-b bg-neutral-800 p-2 font-mono"
					rows="14"
					placeholder="Paste content"
					bind:value={editContent}
				></textarea>
				{#if editError}
					<div class="mb-3 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
						{editError}
					</div>
				{/if}
			{:else}
				<div
					class="flex h-20 w-full items-center justify-center rounded-b bg-neutral-800 text-sm text-neutral-400"
					class:hidden={contentRendered && !editing}
				>
					<span class="monospace">{decryptStatus || 'Loading...'}</span>
				</div>
				<div
					class={data.paste.syntax === 'markdown'
						? 'markdown rounded-b-md bg-neutral-800 p-4'
						: data.paste.syntax === 'csv'
							? 'csv-container scrollbar overflow-x-auto overflow-y-auto scrollbar-thumb-neutral-600 scrollbar-track-neutral-800'
							: 'codeblock-with-lines overflow-x-auto overflow-y-auto'}
					class:hidden={!contentRendered}
					on:click={handleMarkdownClick}
					role="presentation"
				>
					{@html pasteContent}
				</div>
			{/if}
		{:else}
			<h1 class="mb-4 text-center text-4xl font-bold">Paste not found</h1>
			<h2 class="mt-2 text-center text-xl">The paste you are looking for does not exist.</h2>
		{/if}
	</div>

	<style>
		.hljs {
			background-color: var(--color-neutral-800) !important;
		}

		.codeblock-with-lines {
			display: block;
			width: 100%;
			max-width: 100%;
			overflow: hidden;
			flex: 1 1 auto;
		}
		.codeblock-with-lines pre {
			display: block;
			position: relative;
			margin: 0;
			background: none;
			border-bottom-left-radius: 0.25rem;
			border-bottom-right-radius: 0.25rem;
			background-color: var(--color-neutral-800) !important;
			overflow-y: auto;
			overflow-x: hidden;
			box-sizing: border-box;
			min-width: 0;
			width: 100%;
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

		.csv-table {
			border-collapse: separate;
			border-spacing: 0;
			background-color: var(--color-neutral-800);
			border-bottom-left-radius: 0.25rem;
			border-bottom-right-radius: 0.25rem;
			min-width: 100%;
		}

		.csv-table thead th {
			position: sticky;
			top: 0;
			background-color: var(--color-neutral-800);
			border-bottom: 2px solid var(--color-neutral-700);
			z-index: 2;
		}

		.csv-table tbody tr,
		.csv-table thead th {
			border-bottom: 1px solid var(--color-neutral-700);
		}

		.csv-table tbody tr:hover,
		.csv-table thead tr:hover {
			background-color: rgba(255, 255, 255, 0.05);
		}

		.csv-table tbody td,
		.csv-table thead th {
			padding: 0.75rem 1rem;
			text-align: left;
			color: var(--color-neutral-300);
			white-space: nowrap;
		}

		.csv-table tbody tr:last-child {
			border-bottom: none;
		}

		.csv-container {
			max-height: 60vh;
			border-bottom-left-radius: 0.25rem;
			border-bottom-right-radius: 0.25rem;
		}
	</style>
</main>
