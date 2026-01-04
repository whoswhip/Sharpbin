<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageData } from './$types';
    import type { Pagination } from '$lib/types/pagination';
	import { User, CalendarDays, ShieldUser, Ban, File, AtSign, Pencil, Trash2, Clock, Hash } from '@lucide/svelte';
	import { extractDateFromUUIDv7, tooltip, dateToRelativeString } from '$lib/utils/misc';
	import { roles } from '$lib/consts';
    import { getToken, getUserUUIDFromToken } from '$lib/utils/auth';
	import Modal from '$lib/components/Modal.svelte';

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
	let isOwner = false;
	let showEditModal = false;
	let showDeleteModal = false;
	let modalError = '';
	let newDisplayName = '';

	$: {
		const userUUID = getUserUUIDFromToken();
		isOwner = !!userUUID && userUUID === data.user.uuid;
	}

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

	async function handleEditDisplayName(displayName: string) {
		if (!displayName.trim()) {
			modalError = 'Display name cannot be empty';
			return;
		}
		loading = true;
		const token = getToken();
		const res = await fetch(`/api/user/uuid/${data.user.uuid}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify({ displayName: displayName.trim() })
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to update display name';
			return;
		}
		showEditModal = false;
		data.user.displayName = displayName;
		modalError = '';
	}

	async function handleDeleteAccount() {
		loading = true;
		const token = getToken();
		const res = await fetch(`/api/user/uuid/${data.user.uuid}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${token}`
			}
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to delete account';
			return;
		}
		showDeleteModal = false;
		window.location.href = '/';
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
		<div class="mb-2 flex flex-wrap items-center justify-center gap-4 text-sm">
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
			<div class="flex shrink-0 items-center">
				<Hash class="mr-1 h-6 w-6 text-neutral-400" />
				<span class="text-neutral-400" use:tooltip={`User #${data.user.uid}`}>
					{data.user.uid}
				</span>
			</div>
			{#if isOwner && data.user.lastLogin}
				<div class="flex shrink-0 items-center">
					<Clock class="mr-2 h-6 w-6 text-neutral-400" />
					<span
						class="text-neutral-400"
						use:tooltip={new Date(data.user.lastLogin).toLocaleString()}
					>
						Last login {dateToRelativeString(new Date(data.user.lastLogin))}
					</span>
				</div>
			{/if}
		</div>
		{#if isOwner}
			<div class="mt-4 flex gap-2 justify-center flex-wrap">
				<button
					on:click={() => {
						showEditModal = true;
						newDisplayName = data.user.displayName || data.user.username;
						modalError = '';
					}}
					class="flex items-center gap-2 rounded bg-neutral-700 hover:bg-neutral-600 px-4 py-2 text-sm font-medium transition-colors"
				>
					<Pencil class="h-4 w-4" />
					Edit Display Name
				</button>
				<button
					on:click={() => {
						showDeleteModal = true;
						modalError = '';
					}}
					class="flex items-center gap-2 rounded bg-red-900 hover:bg-red-800 px-4 py-2 text-sm font-medium transition-colors"
				>
					<Trash2 class="h-4 w-4" />
					Delete Account
				</button>
			</div>
		{/if}
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
				<p class="text-center text-neutral-400">{isOwner ? 'You have' : 'This user has'} not created any pastes yet.</p>
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

<Modal
	show={showEditModal}
	mode="prompt"
	title="Edit Display Name	"
	placeholder="New Display Name"
	bind:error={modalError}
	onConfirm={(value) => handleEditDisplayName(value as string)}
	onCancel={() => {
		showEditModal = false;
		modalError = '';
	}}
/>

<Modal
	show={showDeleteModal}
	mode="confirm"
	title="Delete Account"
	message="This action cannot be undone. All your pastes and account data will be permanently deleted."
	confirmButtonText="Delete Account"
	error={modalError}
	onConfirm={() => handleDeleteAccount()}
	onCancel={() => {
		showDeleteModal = false;
		modalError = '';
	}}
/>

<style>
	:global(body) {
		margin: 0;
		padding: 0;
	}
</style>
