<script lang="ts">
	import { Bold, Italic, CodeXml, Quote } from '@lucide/svelte';
	import { parseCommentMarkdown } from '$lib/utils/markdown';

	interface Props {
		class?: string;
		value?: string;
		placeholder?: string;
		disabled?: boolean;
		submitting?: boolean;
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
		submitLabel = 'Post comment',
		submittingLabel = 'Posting...',
		onSubmit
	}: Props = $props();

	let editor = $state<HTMLTextAreaElement | null>(null);
	let mode = $state<'preview' | 'raw'>('raw');

	const isDisabled = $derived(disabled || submitting);
	const canSubmit = $derived(!isDisabled && value.trim().length > 0);
	const parsedHtml = $derived(parseCommentMarkdown(value));

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

<div class="mb-4 flex flex-col rounded {className}">
	{#if mode === 'raw'}
		<textarea
			bind:this={editor}
			class="min-h-24 w-full rounded-t border border-b-0 border-neutral-700 bg-neutral-900 p-2 font-mono text-sm text-neutral-100 outline-none"
			{placeholder}
			maxlength={5000}
			disabled={isDisabled}
			bind:value
			onkeydown={handleKeydown}
		></textarea>
	{:else}
		<div
			class="min-h-24 w-full rounded-t border border-b-0 border-neutral-700 bg-neutral-900 p-2 text-sm text-neutral-100"
		>
			{#if value.trim().length === 0}
				<div class="text-neutral-500">{placeholder}</div>
			{:else}
				<div class="text-sm leading-relaxed wrap-break-word text-neutral-200">
					<!-- eslint-disable-next-line svelte/no-at-html-tags -->
					{@html parsedHtml}
				</div>
			{/if}
		</div>
	{/if}
	<div
		class="flex w-full flex-col gap-2 rounded-b border border-neutral-700 bg-neutral-800 p-2 md:flex-row md:gap-0"
	>
		<div class="flex items-center gap-1">
			<button
				type="button"
				class="rounded px-2 py-1 text-sm text-neutral-300 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-600"
				onclick={addBold}
				disabled={isDisabled || mode === 'preview'}
			>
				<Bold class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="rounded px-2 py-1 text-sm text-neutral-300 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-600"
				onclick={addItalic}
				disabled={isDisabled || mode === 'preview'}
			>
				<Italic class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="rounded px-2 py-1 text-sm text-neutral-300 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-600"
				onclick={addQuote}
				disabled={isDisabled || mode === 'preview'}
			>
				<Quote class="h-4 w-4" />
			</button>
			<button
				type="button"
				class="rounded px-2 py-1 text-sm text-neutral-300 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-600"
				onclick={addCode}
				disabled={isDisabled || mode === 'preview'}
			>
				<CodeXml class="h-5 w-5" />
			</button>
		</div>
		<div class="flex flex-col items-center gap-2 md:ml-auto md:flex-row">
			<button
				type="button"
				class="ml-auto w-full rounded border border-neutral-600 px-3 py-1 text-sm text-neutral-200 hover:border-neutral-500 hover:text-neutral-100 md:w-auto"
				onclick={toggleMode}
				disabled={isDisabled}
			>
				{mode === 'preview' ? 'Raw' : 'Preview'}
			</button>
			<button
				type="button"
				class="w-full rounded border border-neutral-600 px-3 py-1 text-sm text-neutral-100 hover:bg-neutral-600 disabled:cursor-not-allowed disabled:border-neutral-700 disabled:text-neutral-500 md:ml-2 md:w-auto"
				onclick={submit}
				disabled={!canSubmit}
			>
				{submitting ? submittingLabel : submitLabel}
			</button>
		</div>
	</div>
</div>
