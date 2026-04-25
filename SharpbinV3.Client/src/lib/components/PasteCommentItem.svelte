<script lang="ts">
	import type { CommentReaction, CommentTreeNode } from '$lib/types/comment';
	import { dateToRelativeString, tooltip } from '$lib/utils/misc';
	import { parseCommentMarkdown } from '$lib/utils/markdown';
	import { escapeHtml } from '$lib/utils/html';
	import { user } from '$lib/stores/user';
	import PasteCommentItem from '$lib/components/PasteCommentItem.svelte';
	import { ThumbsUp, ThumbsDown, Trash2, Shredder } from '@lucide/svelte';
	import { resolve } from '$app/paths';
	import RichTextEditor from './RichTextEditor.svelte';
	import { hasRole } from '$lib/utils/auth';

	interface Props {
		node: CommentTreeNode;
		depth?: number;
		now: Date;
		reactingIds: Record<number, boolean>;
		onReact: (commentId: number, target: 1 | 2, current: CommentReaction) => Promise<void>;
		onReply: (parentCommentID: number, content: string) => Promise<boolean>;
		deleteCommentAction: (commentId: number, hardDelete?: boolean) => Promise<boolean>;
	}

	let {
		node,
		depth = 1,
		now,
		reactingIds,
		onReact,
		onReply,
		deleteCommentAction
	}: Props = $props();
	let deleting = $state(false);

	const maxCommentLength = 320;
	let expanded = $state(false);
	let showDeepReplies = $state(false);
	let replyOpen = $state(false);
	let replyText = $state('');
	let replySubmitting = $state(false);
	let replyError = $state('');
	let replyEditor = $state<{ focus: () => void } | undefined>(undefined);

	let commentText = $derived(node.content ?? '*[Deleted comment]*');
	let isLongComment = $derived(commentText.length > maxCommentLength);
	let isDeleted = $derived(node.content === null);
	let parsedHtml = $derived(
		isDeleted ? escapeHtml(commentText) : parseCommentMarkdown(commentText)
	);
	let authorDisplay = $derived(
		node.author
			? (node.author.displayName?.length || 0) > 0
				? node.author.displayName
				: node.author.username
			: 'Deleted User'
	);

	async function submitReply() {
		replyError = '';
		if (!$user) {
			replyError = 'You must be signed in to reply.';
			return;
		}
		if (!replyText.trim()) {
			replyError = 'Reply cannot be empty.';
			return;
		}
		replySubmitting = true;
		const ok = await onReply(node.id, replyText);
		replySubmitting = false;
		if (ok) {
			replyText = '';
			replyError = '';
			replyOpen = false;
		} else {
			replyError = 'Failed to post reply.';
		}
	}

	function openReply(initialText: string) {
		replyOpen = true;
		replyError = '';
		replyText = initialText;
		queueMicrotask(() => {
			replyEditor?.focus();
		});
	}

	async function handleDelete(hardDelete = false) {
		if (deleting) return;
		deleting = true;
		await deleteCommentAction(node.id, hardDelete);
		deleting = false;
	}
</script>

<div class="p-3">
	<div class="mb-2 flex items-center justify-between gap-3 text-xs text-neutral-400">
		<div class="flex min-w-0 items-center gap-2 text-lg">
			{#if node.author}
				{#if node.author.isBanned}
					<span class="text-red-500">BANNED</span>
				{/if}
				<a
					href={resolve(`/user/${node.author?.username}`)}
					class="flex items-center gap-2 underline"
				>
					<span
						class="truncate font-semibold text-neutral-200 {node.author.isBanned
							? 'line-through decoration-red-500 decoration-2'
							: ''}">{authorDisplay}</span
					>
				</a>
			{/if}
			{#if node.updatedAt}
				<span
					class="text-sm text-neutral-500"
					use:tooltip={`Edited on ${new Date(node.updatedAt * 1000).toLocaleString()} • ${dateToRelativeString(new Date(node.updatedAt * 1000), true, true, now, 3)}`}
					>edited</span
				>
			{/if}
		</div>
		<span class="shrink-0"
			>{dateToRelativeString(new Date(node.createdAt * 1000), true, false, now, 2)}</span
		>
	</div>

	<div class="text-sm leading-relaxed text-neutral-200">
		<div class="wrap-break-word" class:italic={isDeleted} class:text-neutral-800={isDeleted}>
			{#if expanded || !isLongComment}
				<!-- eslint-disable-next-line svelte/no-at-html-tags -->
				{@html parsedHtml}
			{:else}
				<div class="line-clamp-3">
					<!-- eslint-disable-next-line svelte/no-at-html-tags -->
					{@html parsedHtml}
				</div>
			{/if}
		</div>
		{#if isLongComment}
			<button
				type="button"
				class="mt-2 text-xs text-neutral-400 hover:text-neutral-200"
				onclick={() => {
					expanded = !expanded;
				}}
			>
				{expanded ? 'Show less' : 'Show more'}
			</button>
		{/if}
	</div>

	<div class="mt-3 flex flex-wrap items-center gap-2">
		<button
			type="button"
			class="h-7 min-w-12 rounded border px-2 py-1 text-xs {node.userReaction !== 1
				? 'hover:bg-neutral-800 active:bg-neutral-700'
				: 'hover:bg-green-800 active:bg-green-700'}"
			class:border-green-700={node.userReaction === 1}
			class:bg-green-900={node.userReaction === 1}
			class:text-green-200={node.userReaction === 1}
			class:border-neutral-700={node.userReaction !== 1}
			class:text-neutral-300={node.userReaction !== 1}
			onclick={() => onReact(node.id, 1, node.userReaction)}
			disabled={reactingIds[node.id] || !$user}
		>
			<ThumbsUp class="mr-1 inline h-3.5 w-3.5" />
			{node.likes}
		</button>
		<button
			type="button"
			class="h-7 min-w-12 rounded border px-2 py-1 text-xs {node.userReaction !== 2
				? 'hover:bg-neutral-800 active:bg-neutral-700'
				: 'hover:bg-red-800 active:bg-red-700'}"
			class:border-red-700={node.userReaction === 2}
			class:bg-red-900={node.userReaction === 2}
			class:text-red-200={node.userReaction === 2}
			class:border-neutral-700={node.userReaction !== 2}
			class:text-neutral-300={node.userReaction !== 2}
			onclick={() => onReact(node.id, 2, node.userReaction)}
			disabled={reactingIds[node.id] || !$user}
		>
			<ThumbsDown class="mr-1 inline h-3.5 w-3.5" />
			{node.dislikes}
		</button>
		{#if $user}
			{#if !replyOpen}
				<button
					type="button"
					class="h-7 min-w-12 rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800 hover:text-neutral-100 active:bg-neutral-700"
					onclick={() => {
						openReply(node.content ? `> ${node.content.replace(/\n/g, '\n> ')}\n\n` : '');
					}}
				>
					Quote
				</button>
			{/if}
			<button
				type="button"
				class="h-7 min-w-12 rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800 hover:text-neutral-100 active:bg-neutral-700"
				onclick={() => {
					if (replyOpen) {
						replyOpen = false;
						replyError = '';
						replyText = '';
						return;
					}
					openReply('');
				}}
			>
				{replyOpen ? 'Cancel' : 'Reply'}
			</button>
			{#if node.author?.uuid === $user.uuid || hasRole($user.roles, 4) || hasRole($user.roles, 2)}
				<div class="ml-auto">
					<button
						type="button"
						class="h-7 rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800 hover:text-neutral-100 active:bg-neutral-700"
						onclick={() => handleDelete(false)}
						disabled={deleting}
					>
						<Trash2 class="inline h-3.5 w-3.5" />
					</button>
					{#if hasRole($user.roles, 4) || hasRole($user.roles, 2)}
						<button
							type="button"
							class="h-7 rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:bg-neutral-800 hover:text-neutral-100 active:bg-neutral-700"
							onclick={() => handleDelete(true)}
							disabled={deleting}
						>
							<Shredder class="inline h-3.5 w-3.5" />
						</button>
					{/if}
				</div>
			{/if}
		{/if}
	</div>

	{#if replyOpen}
		<RichTextEditor
			class="mt-3"
			bind:this={replyEditor}
			bind:value={replyText}
			placeholder="Write a reply..."
			onSubmit={submitReply}
			disabled={replySubmitting}
			submitting={replySubmitting}
		/>
		{#if replyError}
			<p class="mt-2 text-xs text-red-400">{replyError}</p>
		{/if}
	{/if}

	{#if node.children.length > 0}
		<div class="mt-3 border-l border-neutral-800 pl-3">
			{#if depth >= 3 && !showDeepReplies}
				<button
					type="button"
					class="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:text-neutral-100"
					onclick={() => {
						showDeepReplies = true;
					}}
				>
					Show {node.children.length} more repl{node.children.length === 1 ? 'y' : 'ies'}
				</button>
			{:else}
				<div class="space-y-3">
					{#each node.children as child (child.id)}
						<PasteCommentItem
							node={child}
							depth={depth + 1}
							{now}
							{reactingIds}
							{onReact}
							{onReply}
							{deleteCommentAction}
						/>
					{/each}
				</div>
			{/if}
		</div>
	{/if}
</div>
