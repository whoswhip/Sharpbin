<script lang="ts">
	import { onMount } from 'svelte';
	import { getToken } from '$lib/utils/auth';
	import { user } from '$lib/stores/user';
	import type {
		CommentReaction,
		CommentReactionResult,
		PasteComment,
		CommentTreeNode
	} from '$lib/types/comment';
	import PasteCommentItem from '$lib/components/PasteCommentItem.svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import RichTextEditor from './RichTextEditor.svelte';
	import { openModal } from '$lib/stores/modal';

	interface Props {
		pasteId: string;
		initialComments?: PasteComment[];
	}

	let { pasteId, initialComments = [] }: Props = $props();

	let comments = $derived.by(() => [...initialComments]);
	let loading = $state(false);
	let posting = $state(false);
	let now = $state(new Date());
	let interval: ReturnType<typeof setInterval> | null = null;
	let errorMessage = $state('');
	let newComment = $state('');
	let reactingIds = $state<Record<number, boolean>>({});

	const sortedComments = $derived(
		[...comments].sort((a, b) => {
			if (a.createdAt !== b.createdAt) return a.createdAt - b.createdAt;
			return a.id - b.id;
		})
	);
	const threadedComments = $derived(buildCommentTree(sortedComments));

	onMount(() => {
		interval = setInterval(() => {
			now = new Date();
		}, 1000 * 30);
		void refreshComments();
		return () => {
			if (interval) clearInterval(interval);
		};
	});

	function buildCommentTree(list: PasteComment[]): CommentTreeNode[] {
		const nodes = new SvelteMap<number, CommentTreeNode>();
		const roots: CommentTreeNode[] = [];

		for (const comment of list) {
			nodes.set(comment.id, {
				...comment,
				children: []
			});
		}

		for (const node of nodes.values()) {
			if (node.parentCommentID && nodes.has(node.parentCommentID)) {
				nodes.get(node.parentCommentID)?.children.push(node);
			} else {
				roots.push(node);
			}
		}

		return roots;
	}

	async function refreshComments() {
		loading = true;
		errorMessage = '';
		const token = getToken();
		const headers = new Headers();
		if (token) headers.set('Authorization', `Bearer ${token}`);
		try {
			const res = await fetch(`/api/paste/${pasteId}/comments`, { headers });
			if (!res.ok) {
				errorMessage = 'Failed to load comments.';
				loading = false;
				return;
			}
			const json = await res.json();
			comments = Array.isArray(json?.comments) ? (json.comments as PasteComment[]) : [];
		} catch {
			errorMessage = 'Failed to load comments.';
		} finally {
			loading = false;
		}
	}

	async function postComment(content: string, parentCommentID: number | null): Promise<boolean> {
		errorMessage = '';
		const token = getToken();
		if (!token) {
			errorMessage = 'You must be signed in to comment.';
			return false;
		}
		const trimmed = content.trim();
		if (!trimmed) {
			errorMessage = 'Comment cannot be empty.';
			return false;
		}

		if (parentCommentID === null) posting = true;
		try {
			const res = await fetch(`/api/paste/${pasteId}/comments`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ content: trimmed, parentCommentID })
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				errorMessage = err?.message || 'Failed to post comment.';
				return false;
			}
			const json = await res.json();
			const created = json?.comment as PasteComment | undefined;
			if (!created) {
				errorMessage = 'Failed to post comment.';
				return false;
			}
			comments = [...comments, created];
			if (parentCommentID === null) newComment = '';
			return true;
		} catch {
			errorMessage = 'Failed to post comment.';
			return false;
		} finally {
			if (parentCommentID === null) posting = false;
		}
	}

	async function reactToComment(commentId: number, target: 1 | 2, current: CommentReaction) {
		errorMessage = '';
		const token = getToken();
		if (!token) {
			errorMessage = 'You must be signed in to react.';
			return;
		}

		reactingIds = { ...reactingIds, [commentId]: true };
		const nextReaction: CommentReaction = current === target ? null : target;
		try {
			const res = await fetch(`/api/paste/${pasteId}/comments/${commentId}/reaction`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ reaction: nextReaction })
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				errorMessage = err?.message || 'Failed to apply reaction.';
				return;
			}
			const json = await res.json();
			const reaction = json?.reaction as CommentReactionResult | undefined;
			if (!reaction) {
				errorMessage = 'Failed to apply reaction.';
				return;
			}
			comments = comments.map((comment) =>
				comment.id === commentId
					? {
							...comment,
							likes: reaction.likes,
							dislikes: reaction.dislikes,
							userReaction: reaction.userReaction
						}
					: comment
			);
		} catch {
			errorMessage = 'Failed to apply reaction.';
		} finally {
			const next = { ...reactingIds };
			delete next[commentId];
			reactingIds = next;
		}
	}

	async function submitTopLevelComment(content: string) {
		await postComment(content, null);
	}

	async function deleteComment(commentId: number, hardDelete = false): Promise<boolean> {
		errorMessage = '';
		const token = getToken();
		if (!token) {
			errorMessage = 'You must be signed in to delete comments.';
			return false;
		}

		const title = hardDelete ? 'Hard delete comment?' : 'Delete comment?';
		const message = hardDelete
			? 'This permanently removes the comment from the thread. This cannot be undone.'
			: 'This will remove the comment content while preserving the thread structure.';
		const confirmButtonText = hardDelete ? 'Hard delete' : 'Delete';
		const ok = await openModal<boolean>({
			mode: 'confirm',
			title,
			message,
			confirmButtonText,
			cancelValue: false
		});
		if (!ok) {
			return false;
		}

		try {
			const query = hardDelete ? '?hardDelete=true' : '';
			const res = await fetch(`/api/paste/${pasteId}/comments/${commentId}${query}`, {
				method: 'DELETE',
				headers: {
					Authorization: `Bearer ${token}`
				}
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({}));
				errorMessage = err?.message || 'Failed to delete comment.';
				return false;
			}

			await refreshComments();
			return true;
		} catch {
			errorMessage = 'Failed to delete comment.';
			return false;
		}
	}
</script>

<section id="comments-section" class="mt-6 rounded border border-neutral-800 p-4">
	<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
		<h2 class="text-xl font-semibold text-neutral-100">Comments ({comments.length})</h2>
		<button
			type="button"
			class="rounded border border-neutral-700 px-2 py-1 text-xs text-neutral-300 hover:text-neutral-100"
			onclick={refreshComments}
			disabled={loading}
		>
			{loading ? 'Refreshing...' : 'Refresh'}
		</button>
	</div>

	{#if $user}
		<RichTextEditor
			bind:value={newComment}
			placeholder="Write a comment..."
			onSubmit={submitTopLevelComment}
			disabled={posting}
			submitting={posting}
		/>
	{:else}
		<div class="mb-4 rounded border border-neutral-800 p-3 text-sm text-neutral-400">
			Sign in to post comments and reactions.
		</div>
	{/if}

	{#if errorMessage}
		<div class="mb-4 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
			{errorMessage}
		</div>
	{/if}

	{#if loading && comments.length === 0}
		<div class="rounded border border-neutral-800 p-3 text-sm text-neutral-400">
			Loading comments...
		</div>
	{:else if threadedComments.length === 0}
		<div class="rounded border border-neutral-800 p-3 text-sm text-neutral-400">
			No comments yet.
		</div>
	{:else}
		<div class="space-y-3">
			{#each threadedComments as node (node.id)}
				<PasteCommentItem
					{node}
					{now}
					{reactingIds}
					onReact={reactToComment}
					onReply={(parentCommentID, content) => postComment(content, parentCommentID)}
					deleteCommentAction={deleteComment}
				/>
			{/each}
		</div>
	{/if}
</section>
