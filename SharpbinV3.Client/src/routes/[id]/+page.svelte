<script lang="ts">
	import type { PageData } from './$types';
	import { FileBox, Eye, User, CalendarDays, CalendarOff, Code } from '@lucide/svelte/icons/index';
	import {
		formatBytes,
		extractDateFromUUIDv7,
		dateToRelativeString,
		tooltip
	} from '$lib/utils/misc';
	import { displayNames } from '$lib/consts';
	import { fade } from 'svelte/transition';
	import { resolve } from '$app/paths';
	export let data: PageData;

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
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div
		class="max-h-[80vh] w-[95%] max-w-5xl rounded border-2 border-neutral-800 bg-neutral-900 p-4"
	>
		{#if data.paste}
			<h1
				use:tooltip={data.paste.title || 'Untitled Paste'}
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
						title={extractDateFromUUIDv7(data.paste.uuid)?.toLocaleString() ?? 'Unknown Date'}
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
			<div
				class="codeblock-with-lines max-w-full overflow-x-auto overflow-y-auto"
				style="max-width:100vw; min-width:0;"
			>
				{@html addLineNumbers(data.highlighted ?? '')}
			</div>
		{:else}
			<h1 class="mb-4 text-center text-4xl font-bold">Paste not found</h1>
			<h2 class="mt-2 text-center text-xl">The paste you are looking for does not exist.</h2>
		{/if}
	</div>

	<style>
		.codeblock-with-lines {
			max-width: 100vw;
			min-width: 0;
			overflow-x: auto;
			overflow-y: auto;
		}
		.codeblock-with-lines pre {
			display: block;
			position: relative;
			padding: 1em;
			margin: 0;
			background: none;
			border-radius: 0.25em;
			background-color: var(--color-neutral-800) !important;
			overflow-x: auto;
			min-width: max-content;
			max-height: 60vh;
		}
		.code-row {
			display: flex;
			align-items: flex-start;
			min-width: max-content;
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
			white-space: pre;
			word-break: normal;
			overflow-wrap: normal;
			padding-left: 0.25em;
			min-width: 0;
		}
	</style>
</main>
