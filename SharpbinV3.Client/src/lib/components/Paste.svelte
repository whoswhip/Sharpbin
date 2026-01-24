<script lang="ts">
	import {
		tooltip,
		dateToRelativeString,
		extractDateFromUUIDv7,
		formatNumber,
		formatBytes
	} from '$lib/utils/misc';
	import { resolve } from '$app/paths';
	import { Eye, FileBox, Code, User, History, Calendar, Timer } from '@lucide/svelte';
	import { syntaxes } from '$lib/consts';
	import type { Paste } from '$lib/types/paste';

	export let paste: Paste;
	export let now: Date;

	const createdAt = extractDateFromUUIDv7(paste.uuid);
	const syntax = syntaxes[paste.syntax] ?? syntaxes['plaintext'];
</script>

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
				use:tooltip={`${createdAt?.toLocaleString()} • ${dateToRelativeString(createdAt ?? new Date(), true, false, now)}`}
			>
				<Calendar class="h-4 w-4" />
				<span>
					{#if createdAt}
						{#if createdAt.getTime() > Date.now() - 86_400_000}
							Created {dateToRelativeString(createdAt, true, false, now)}
						{:else}
							Created on {createdAt.toLocaleDateString()}
						{/if}
					{:else}
						Creation date unknown
					{/if}
				</span>
			</div>
			{#if paste.expiresAt > 0}
				<div
					class="mt-1 flex items-center gap-2 text-sm text-neutral-400"
					use:tooltip={new Date(paste.expiresAt).toLocaleString()}
				>
					<Timer class="h-4 w-4" />
					<span>
						{paste.expiresAt > 0 && paste.expiresAt < Date.now()
							? `Expired ${dateToRelativeString(new Date(paste.expiresAt), true, false, now)}`
							: `Expires in ${dateToRelativeString(new Date(paste.expiresAt), true, false, now)}`}
					</span>
				</div>
			{/if}
			<div class="mt-1 flex items-center gap-2 text-sm text-neutral-400">
				<User class="h-4 w-4" />
				<span>{paste.author?.username ?? 'Anonymous'}</span>
			</div>
			{#if paste.editedAt}
				<div
					class="mt-1 flex items-center gap-2 text-sm text-neutral-400"
					use:tooltip={new Date(paste.editedAt).toLocaleString()}
				>
					<History class="h-4 w-4" />
					<span>Edited {dateToRelativeString(new Date(paste.editedAt), true, false, now)}</span>
				</div>
			{/if}
		</div>
		<div>
			<div class="flex items-center gap-2 text-sm text-neutral-400">
				<Eye class="h-4 w-4" />
				<span>{formatNumber(paste.views)} View{paste.views !== 1 ? 's' : ''}</span>
			</div>
			<div
				class="mt-1 flex items-center gap-2 text-sm text-neutral-400"
				use:tooltip={paste.isCompressed ? `Compressed Size: ${formatBytes(paste.size)}` : ''}
			>
				<FileBox class="h-4 w-4" />
				<span>{formatBytes(paste.trueSize)}</span>
			</div>
			<div class="mt-1 flex items-center gap-2 text-sm text-neutral-400">
				<Code class="h-4 w-4" />
				<span>{syntax.name}</span>
			</div>
		</div>
	</div>
</a>
