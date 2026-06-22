<script lang="ts">
	import { Bold, Italic, CodeXml, Quote, Send, Eye, Pencil } from '@lucide/svelte';
	import { parseCommentMarkdown } from '$lib/utils/markdown';

	interface Props {
		class?: string;
		value?: string;
		placeholder?: string;
		disabled?: boolean;
		submitting?: boolean;
		compact?: boolean;
		submitLabel?: string;
		submittingLabel?: string;
		onSubmit?: (value: string) => void | Promise<void>;
	}

	let {
		class: className = '',
		value = $bindable(''),
		placeholder = 'Write a comment...',
		disabled = false,
		submitting = false,
		compact = false,
		submitLabel = 'Post comment',
		submittingLabel = 'Posting...',
		onSubmit
	}: Props = $props();

	let editor = $state<HTMLTextAreaElement | null>(null);
	let mode = $state<'preview' | 'raw'>('raw');

	const isDisabled = $derived(disabled || submitting);
	const canSubmit = $derived(!isDisabled && value.trim().length > 0);
	const parsedHtml = $derived(parseCommentMarkdown(value));
	const editorMinHeight = $derived(compact ? 'min-h-20' : 'min-h-24');

	function focusEditor() {
		editor?.focus();
	}

	export function focus() {
		focusEditor();
	}

	function toggleMode() {
		mode = mode === 'preview' ? 'raw' : 'preview';
		queueMicrotask(focusEditor);
	}

	function replaceSelection(replacement: string, selectionStart: number, selectionEnd: number) {
		value = `${value.slice(0, selectionStart)}${replacement}${value.slice(selectionEnd)}`;
	}

	function wrapSelection(prefix: string, suffix: string, fallback: string) {
		if (!editor) {
			value = `${value}${prefix}${fallback}${suffix}`;
			return;
		}

		const selectionStart = editor.selectionStart;
		const selectionEnd = editor.selectionEnd;
		const selectedText = value.slice(selectionStart, selectionEnd);
		const inner = selectedText.length > 0 ? selectedText : fallback;
		const replacement = `${prefix}${inner}${suffix}`;
		const cursorStart = selectionStart + prefix.length;
		const cursorEnd = cursorStart + inner.length;

		replaceSelection(replacement, selectionStart, selectionEnd);
		queueMicrotask(() => {
			if (!editor) return;
			editor.focus();
			editor.setSelectionRange(cursorStart, cursorEnd);
		});
	}

	function addBold() {
		wrapSelection('**', '**', 'text');
	}

	function addItalic() {
		wrapSelection('*', '*', 'text');
	}

	function addCode() {
		wrapSelection('`', '`', 'code');
	}

	function addQuote() {
		if (!editor) {
			value = `${value}${value.length > 0 && !value.endsWith('\n') ? '\n' : ''}> `;
			return;
		}

		const selectionStart = editor.selectionStart;
		const selectionEnd = editor.selectionEnd;
		const selectedText = value.slice(selectionStart, selectionEnd);

		if (selectedText.length === 0) {
			const needsNewline = selectionStart > 0 && !value.slice(0, selectionStart).endsWith('\n');
			const insert = `${needsNewline ? '\n' : ''}> `;
			const nextCaret = selectionStart + insert.length;
			replaceSelection(insert, selectionStart, selectionEnd);
			queueMicrotask(() => {
				if (!editor) return;
				editor.focus();
				editor.setSelectionRange(nextCaret, nextCaret);
			});
			return;
		}

		const quoted = selectedText
			.split('\n')
			.map((line) => (line.startsWith('> ') ? line : `> ${line}`))
			.join('\n');
		replaceSelection(quoted, selectionStart, selectionEnd);
		queueMicrotask(() => {
			if (!editor) return;
			editor.focus();
			editor.setSelectionRange(selectionStart, selectionStart + quoted.length);
		});
	}

	async function submit() {
		if (!canSubmit || !onSubmit) return;
		await onSubmit(value);
		if (mode === 'raw') {
			queueMicrotask(focusEditor);
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
			event.preventDefault();
			void submit();
		}
	}
</script>

<div
	class="mb-4 overflow-hidden rounded border border-neutral-700 bg-neutral-900 shadow-sm {className}"
>
	{#if mode === 'raw'}
		<textarea
			bind:this={editor}
			class="{editorMinHeight} w-full resize-y border-0 bg-neutral-900 p-3 font-mono text-sm text-neutral-100 placeholder:text-neutral-400 focus:bg-neutral-800/60"
			{placeholder}
			maxlength={5000}
			disabled={isDisabled}
			bind:value
			onkeydown={handleKeydown}
		></textarea>
	{:else}
		<div class="{editorMinHeight} w-full overflow-auto bg-neutral-900 p-3 text-sm text-neutral-100">
			{#if value.trim().length === 0}
				<div class="text-neutral-400">{placeholder}</div>
			{:else}
				<div class="text-sm leading-relaxed wrap-break-word text-neutral-200">
					<!-- eslint-disable-next-line svelte/no-at-html-tags -->
					{@html parsedHtml}
				</div>
			{/if}
		</div>
	{/if}
	<div
		class="flex w-full flex-col gap-2 border-t border-neutral-700 bg-neutral-800 p-2 md:flex-row md:items-center md:gap-0"
	>
		<div class="flex items-center gap-1">
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded text-neutral-300 hover:bg-neutral-700 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-500"
				onclick={addBold}
				disabled={isDisabled || mode === 'preview'}
				aria-label="Bold"
				title="Bold"
			>
				<Bold class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded text-neutral-300 hover:bg-neutral-700 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-500"
				onclick={addItalic}
				disabled={isDisabled || mode === 'preview'}
				aria-label="Italic"
				title="Italic"
			>
				<Italic class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded text-neutral-300 hover:bg-neutral-700 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-500"
				onclick={addQuote}
				disabled={isDisabled || mode === 'preview'}
				aria-label="Quote"
				title="Quote"
			>
				<Quote class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded text-neutral-300 hover:bg-neutral-700 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-500"
				onclick={addCode}
				disabled={isDisabled || mode === 'preview'}
				aria-label="Inline code"
				title="Inline code"
			>
				<CodeXml class="h-4 w-4" />
			</button>
		</div>
		<div class="flex flex-col items-stretch gap-2 md:ml-auto md:flex-row md:items-center">
			<button
				type="button"
				class="flex h-8 w-full items-center justify-center gap-2 rounded px-3 text-sm text-neutral-200 hover:bg-neutral-700 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-500 md:w-auto"
				onclick={toggleMode}
				disabled={isDisabled}
			>
				{#if mode === 'preview'}
					<Pencil class="h-4 w-4" />
				{:else}
					<Eye class="h-4 w-4" />
				{/if}
				{mode === 'preview' ? 'Raw' : 'Preview'}
			</button>
			<button
				type="button"
				class="flex h-8 w-full items-center justify-center gap-2 rounded border border-neutral-600 bg-neutral-700 px-3 text-sm font-medium text-neutral-100 hover:border-neutral-500 hover:bg-neutral-600 disabled:cursor-not-allowed disabled:border-neutral-700 disabled:bg-neutral-800 disabled:text-neutral-500 md:w-auto"
				onclick={submit}
				disabled={!canSubmit}
			>
				<Send class="h-4 w-4" />
				{submitting ? submittingLabel : submitLabel}
			</button>
		</div>
	</div>
</div>
