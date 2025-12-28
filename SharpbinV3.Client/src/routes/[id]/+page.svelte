<script lang="ts">
	import type { PageData } from './$types';
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
	{#if data.paste}
		<div class="max-h-[80vh] rounded border-2 border-neutral-800 bg-neutral-900 p-4 w-full max-w-5xl">
			<h1 class="mb-4 text-center text-4xl font-bold">{data.paste.title || 'Untitled Paste'}</h1>
			<div
				class="codeblock-with-lines max-w-full overflow-x-auto overflow-y-auto"
				style="max-width:100vw; min-width:0;"
			>
				{@html addLineNumbers(data.highlighted ?? '')}
			</div>
		</div>
	{:else}
		<h1 class="text-2xl font-bold">Paste not found</h1>
		<h2 class="mt-2 text-lg">The paste you are looking for does not exist.</h2>
	{/if}
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
