<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageData } from './$types';
    import type { Pagination } from '$lib/types/pagination';
	import { User, CalendarDays, ShieldUser, Ban, File, AtSign } from '@lucide/svelte';
	import { extractDateFromUUIDv7, tooltip } from '$lib/utils/misc';
	import { roles } from '$lib/consts';
    import { getToken } from '$lib/utils/auth';

	export let data: PageData;

	let currentPage = data.user.pagination?.page ?? 1;
	let pagination: Pagination = data.user.pagination ?? {
        page: 1,
        pageSize: 50,
        totalCount: 0,
        totalPages: 1
    };
	let pastes = data.user.pastes ?? [];
	let loading = false;

	async function fetchPage(pageNum: number) {
		if (pageNum < 1 || pageNum > (pagination.totalPages || 1) || loading) return;
		loading = true;
        const token = getToken();
        const res = await fetch(
            `/api/user/${data.user.username}?page=${pageNum}`,
            {
                headers: token ? { Authorization: `Bearer ${token}` } : {}
            }
        );
		if (!res.ok) {
			loading = false;
			return;
		}
		const json = await res.json();
		pastes = json.pastes ?? [];
		pagination = json.pagination ?? pagination;
		currentPage = pagination.page ?? pageNum;
		loading = false;
	}
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
					>{pagination.totalCount} paste{pagination.totalCount !== 1 ? 's' : ''}</span
				>
			</div>
		</div>
		<div class="mt-6 max-h-[60vh] space-y-4 overflow-y-auto">
			{#if pastes && pastes.length > 0}
				{#each pastes.slice().sort((a, b) => b.uuid.localeCompare(a.uuid)) as paste (paste.uuid)}
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
		{#if pagination.totalPages && pagination.totalPages > 1}
			<div class="mt-4 flex items-center justify-center gap-4">
				<button
					class="rounded bg-neutral-700 px-3 py-1 disabled:opacity-50"
					on:click={() => fetchPage(currentPage - 1)}
					disabled={currentPage === 1 || loading}
				>
					Prev
				</button>
				<span class="text-neutral-400">
					Page {currentPage} of {pagination.totalPages}
				</span>
				<button
					class="rounded bg-neutral-700 px-3 py-1 disabled:opacity-50"
					on:click={() => fetchPage(currentPage + 1)}
					disabled={currentPage === pagination.totalPages || loading}
				>
					Next
				</button>
			</div>
		{/if}
	</div>
</main>
