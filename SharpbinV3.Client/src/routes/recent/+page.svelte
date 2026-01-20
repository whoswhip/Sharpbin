<script lang="ts">
	import type { PageData } from './$types';
	import { extractDateFromUUIDv7, dateToRelativeString } from '$lib/utils/misc';
	import { resolve } from '$app/paths';
	export let data: PageData;
</script>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		{#if data.recentPastes.length === 0}
			<p class="text-lg">No recent pastes available.</p>
		{:else}
			<h1 class="mb-4 text-3xl font-bold">Recent Pastes</h1>
			<div class="grid grid-cols-1 gap-4">
				{#each data.recentPastes as paste}
					{@const createdAt = extractDateFromUUIDv7(paste.uuid)}
					<a
						href={resolve(`/${paste.id}`)}
						class="flex flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
					>
						<span class="truncate text-lg font-semibold text-neutral-100 hover:text-white">
							{paste.title || 'Untitled Paste'}
						</span>
						<p class="text-sm text-neutral-400">
							{#if createdAt}
								{#if createdAt.getTime() > Date.now() - 86_400_000}
									Created {dateToRelativeString(createdAt)}
								{:else}
									Created on {createdAt.toLocaleDateString()}
								{/if}
							{:else}
								Creation date unknown
							{/if}
						</p>
					</a>
				{/each}
			</div>
		{/if}
	</div>
</main>
