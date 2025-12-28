<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageData } from './$types';
	import { User, CalendarDays, ShieldUser, Ban, File, AtSign } from '@lucide/svelte';
	import { extractDateFromUUIDv7, tooltip } from '$lib/utils/misc';
	import { roles } from '$lib/consts';

	export let data: PageData;
</script>

<main
	class="flex min-h-screen w-full flex-col items-center justify-center bg-neutral-950 text-white"
>
	<div class="w-[95%] max-w-5xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="flex items-center justify-center gap-4 text-center text-4xl font-bold">
			{#if data.user.roles.includes(1) || data.user.roles.includes(255)}
				{#if Math.max(...data.user.roles.filter((r) => r !== 403)) !== -Infinity}
					<span
						use:tooltip={roles[
							Math.max(...data.user.roles.filter((r) => r !== 403)) as keyof typeof roles
						]}
					>
						<ShieldUser class="h-8 w-8 text-neutral-400" />
					</span>
				{:else}
					<span use:tooltip={'User'}>
						<User class="h-8 w-8 text-neutral-400" />
					</span>
				{/if}
			{:else if data.user.roles.includes(403)}
				<span class="relative flex items-center justify-center" use:tooltip={roles[403]}>
					<User class="h-8 w-8 text-neutral-500 opacity-90" />
					<Ban class="absolute h-7 w-7 text-red-500" />
				</span>
			{:else}
				<span use:tooltip={'User'}>
					<User class="h-8 w-8 text-neutral-400" />
				</span>
			{/if}
			{data.user.displayName || data.user.username}
		</h1>
		{#if data.user.displayName && data.user.displayName !== data.user.username}
			<div class="mb-2 flex items-center justify-center">
				<AtSign class="mr-2 inline h-5 w-5 text-neutral-400" />
				<span class="text-neutral-400">{data.user.username}</span>
			</div>
		{/if}
		<div class="mb-2 flex flex-wrap items-center justify-center gap-4">
			<div class="flex shrink-0 items-center">
				<CalendarDays class="mr-2 h-6 w-6 text-neutral-400" />
				<span
					class="text-neutral-400"
					use:tooltip={extractDateFromUUIDv7(data.user.uuid)?.toLocaleString() ?? 'Unknown'}
				>
					Joined {extractDateFromUUIDv7(data.user.uuid)?.toLocaleDateString() ?? 'Unknown'}
				</span>
			</div>
			<div class="flex shrink-0 items-center">
				<File class="mr-2 h-6 w-6 text-neutral-400" />
				<span class="text-neutral-400"
					>{data.user.pastes?.length} paste{data.user.pastes?.length !== 1 ? 's' : ''}</span
				>
			</div>
		</div>
		<div class="mt-6 max-h-[60vh] space-y-4 overflow-y-auto">
			{#if data.user.pastes && data.user.pastes.length > 0}
				{#each data.user.pastes as paste}
					<a
						href={resolve(`/${paste.id}`)}
						class="flex flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
					>
						<span class="truncate text-lg font-semibold text-neutral-100 hover:text-white">
							{paste.title || 'Untitled Paste'}
						</span>
						<p class="text-sm text-neutral-400">
							Created on {extractDateFromUUIDv7(paste.uuid)?.toLocaleDateString() ?? 'Unknown Date'}
						</p>
					</a>
				{/each}
			{:else}
				<p class="text-center text-neutral-400">This user has not created any pastes yet.</p>
			{/if}
		</div>
	</div>
</main>
