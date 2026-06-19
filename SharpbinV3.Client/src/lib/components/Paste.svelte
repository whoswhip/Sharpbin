<script lang="ts">
	import { tooltip, dateToRelativeString, formatNumber, formatBytes } from '$lib/utils/misc';
	import { resolve } from '$app/paths';
	import {
		Eye,
		FileBox,
		Code,
		User,
		History,
		CalendarDays,
		CalendarOff,
		Lock,
		EyeOff,
		Globe,
		HatGlasses,
		ThumbsUp
	} from '@lucide/svelte';
	import { syntaxes } from '$lib/consts';
	import type { Paste } from '$lib/types/paste';

	interface Props {
		paste: Paste;
		now: Date;
		showUser?: boolean;
		compact?: boolean;
	}

	let { paste, now, showUser = true, compact = false }: Props = $props();

	let syntax = $derived(syntaxes[paste.syntax] ?? syntaxes['plaintext']);
	let netLikes = $derived(paste.likes - paste.dislikes);
	let netLikeText = $derived(`${formatNumber(netLikes)} Like${netLikes === 1 ? '' : 's'}`);
</script>

{#if compact}
	<a
		href={resolve(`/${paste.id}`)}
		class="flex flex-col gap-1 rounded border border-neutral-700 bg-neutral-800 px-4 py-3 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
	>
		<div class="flex w-full flex-row justify-between">
			<span
				class="text-md w-fit max-w-full truncate font-semibold text-neutral-100 hover:text-white"
				use:tooltip={paste.title || 'Untitled Paste'}
			>
				{paste.title || 'Untitled Paste'}
			</span>
			<div
				class="flex items-center gap-2 text-sm text-neutral-400"
				use:tooltip={`${new Date(paste.createdAt).toLocaleString()} • ${dateToRelativeString(new Date(paste.createdAt), true, false, now)}`}
			>
				<CalendarDays class="h-4 w-4" />
				{#if paste.createdAt}
					{#if paste.createdAt > Date.now() - 86_400_000}
						Created {dateToRelativeString(new Date(paste.createdAt), true, false, now)}
					{:else}
						{new Date(paste.createdAt).toLocaleDateString()}
					{/if}
				{:else}
					Creation date unknown
				{/if}
			</div>
		</div>

		<div class="flex flex-row justify-between text-sm text-neutral-400">
			<div>
				{#if showUser}
					<div class="flex items-center gap-2">
						{#if paste.author}
							<User class="h-4 w-4" />
						{:else}
							<HatGlasses class="h-4 w-4" />
						{/if}
						{paste.author?.username ?? 'Anonymous'}
					</div>
				{:else}
					<div class="flex items-center gap-2">
						{#if paste.visibility === 0}
							<Globe class="h-4 w-4" />
							Public
						{:else if paste.visibility === 1}
							<EyeOff class="h-4 w-4" />
							Unlisted
						{:else}
							<Lock class="h-4 w-4" />
							Private
						{/if}
					</div>
				{/if}
				<div class="flex flex-wrap items-center gap-x-3 gap-y-1">
					<span class="flex items-center gap-2">
						<Eye class="h-4 w-4" />
						{formatNumber(paste.views)} View{paste.views !== 1 ? 's' : ''}
					</span>
					<span
						class="flex items-center gap-2"
						use:tooltip={`${formatNumber(paste.likes)} likes, ${formatNumber(paste.dislikes)} dislikes`}
					>
						<ThumbsUp class="h-4 w-4" />
						{netLikeText}
					</span>
				</div>
			</div>
			<div>
				<div
					class="flex items-center gap-2"
					use:tooltip={paste.isCompressed
						? `Compressed Size: ${formatBytes(paste.storedSize)}`
						: ''}
				>
					<FileBox class="h-4 w-4" />
					{formatBytes(paste.originalSize)}
				</div>
				<div class="flex items-center gap-2">
					<Code class="h-4 w-4" />
					{syntax.name}
				</div>
			</div>
		</div>
	</a>
{:else}
	<a
		href={resolve(`/${paste.id}`)}
		class="flex flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
	>
		<span
			class="w-fit max-w-full truncate text-lg font-semibold text-neutral-100 hover:text-white"
			use:tooltip={paste.title || 'Untitled Paste'}
		>
			{paste.title || 'Untitled Paste'}
		</span>
		<div class="flex flex-row justify-between">
			<div>
				<div
					class="flex items-center gap-2 text-sm text-neutral-400"
					use:tooltip={`${new Date(paste.createdAt).toLocaleString()} • ${dateToRelativeString(new Date(paste.createdAt), true, false, now)}`}
				>
					<CalendarDays class="h-4 w-4" />
					<span>
						{#if paste.createdAt}
							{#if paste.createdAt > Date.now() - 86_400_000}
								Created {dateToRelativeString(new Date(paste.createdAt), true, false, now)}
							{:else}
								Created on {new Date(paste.createdAt).toLocaleDateString()}
							{/if}
						{:else}
							Creation date unknown
						{/if}
					</span>
				</div>
				{#if paste.editedAt && paste.editedAt != 0}
					<div
						class="mt-1 flex items-center gap-2 text-sm text-neutral-400"
						use:tooltip={new Date(paste.editedAt).toLocaleString()}
					>
						<History class="h-4 w-4" />
						<span>
							{#if paste.editedAt > Date.now() - 86_400_000}
								Edited {dateToRelativeString(new Date(paste.editedAt), true, false, now)}
							{:else}
								Edited on {new Date(paste.editedAt).toLocaleDateString()}
							{/if}
						</span>
					</div>
				{/if}
				{#if paste.expiresAt > 0}
					<div
						class="mt-1 flex items-center gap-2 text-sm text-neutral-400"
						use:tooltip={new Date(paste.expiresAt).toLocaleString()}
					>
						<CalendarOff class="h-4 w-4" />
						<span>
							{paste.expiresAt > 0 && paste.expiresAt < Date.now()
								? `Expired ${dateToRelativeString(new Date(paste.expiresAt), true, false, now)}`
								: `Expires in ${dateToRelativeString(new Date(paste.expiresAt), true, false, now)}`}
						</span>
					</div>
				{/if}
				{#if showUser}
					<div class="mt-1 flex items-center gap-2 text-sm text-neutral-400">
						{#if paste.author}
							<User class="h-4 w-4" />
						{:else}
							<HatGlasses class="h-4 w-4" />
						{/if}
						<span>{paste.author?.username ?? 'Anonymous'}</span>
					</div>
				{/if}
			</div>
			<div class="grid grid-cols-[auto_auto] gap-x-4 gap-y-1 text-sm text-neutral-400">
				<div class="flex items-center gap-2">
					<Eye class="h-4 w-4" />
					<span>{formatNumber(paste.views)} View{paste.views !== 1 ? 's' : ''}</span>
				</div>
				<div
					class="flex items-center gap-2"
					use:tooltip={`${formatNumber(paste.likes)} likes, ${formatNumber(paste.dislikes)} dislikes`}
				>
					<ThumbsUp class="h-4 w-4" />
					<span>{netLikeText}</span>
				</div>
				<div
					class="flex items-center gap-2"
					use:tooltip={paste.isCompressed
						? `Compressed Size: ${formatBytes(paste.storedSize)}`
						: ''}
				>
					<FileBox class="h-4 w-4" />
					<span>{formatBytes(paste.originalSize)}</span>
				</div>
				<div class="flex items-center gap-2">
					<Code class="h-4 w-4" />
					<span>{syntax.name}</span>
				</div>
			</div>
		</div>
	</a>
{/if}
