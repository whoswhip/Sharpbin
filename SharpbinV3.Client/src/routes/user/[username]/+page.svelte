<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageData } from './$types';
	import type { Pagination } from '$lib/types/pagination';
	import {
		User,
		CalendarDays,
		ShieldUser,
		Ban,
		File,
		AtSign,
		Pencil,
		Trash2,
		Clock,
		Hash
	} from '@lucide/svelte';
	import { extractDateFromUUIDv7, tooltip, dateToRelativeString } from '$lib/utils/misc';
	import { roles } from '$lib/consts';
	import { getToken } from '$lib/utils/auth';
	import { needsAdminTotp } from '$lib/utils/totp';
	import Modal from '$lib/components/Modal.svelte';
	import { user } from '$lib/stores/user';
	import { onMount } from 'svelte';

	export let data: PageData;

	let currentPage = data.user?.pagination?.page ?? 1;
	let pagination: Pagination = data.user?.pagination ?? {
		page: 1,
		pageSize: 50,
		totalCount: 0,
		totalPages: 1
	};
	let pastes = data.user?.pastes ?? [];
	let loading = false;
	let isOwner = false;
	let showEditModal = false;
	let showDeleteModal = false;
	let showRoleModal = false;
	let showTotpModal = false;
	let showRoleTotpModal = false;
	let showDeleteTotpModal = false;
	let modalError = '';
	let totpEnabled = false;
	let pendingRoles: number[] | null = null;
	let roleTotpCode = '';
	let deleteTotpCode = '';
	let now = new Date();
	let interval: ReturnType<typeof setInterval> | null = null;

	$: isOwner = data.user && $user ? data.user?.uuid === $user.uuid : false;
	$: totpEnabled = Boolean($user?.totpEnabled);

	const roleOptions = [
		{ label: 'Member', value: 0 },
		{ label: 'Moderator', value: 1 },
		{ label: 'Administrator', value: 255 },
		{ label: 'Banned', value: 403 }
	];

	async function fetchPage(pageNum: number) {
		if (pageNum < 1 || pageNum > (pagination.totalPages || 1) || loading) return;
		loading = true;
		const token = getToken();
		const res = await fetch(`/api/user/${data.user?.username}?page=${pageNum}`, {
			headers: token ? { Authorization: `Bearer ${token}` } : {}
		});
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

	async function handleUserUpdate(displayName?: string, selectedRoles?: number[]) {
		loading = true;
		modalError = '';
		const token = getToken();
		const currentRoles = data.user?.roles ?? [];
		const nextRoles = selectedRoles ?? currentRoles;
		if (needsAdminTotp(totpEnabled, currentRoles, nextRoles) && !roleTotpCode) {
			pendingRoles = nextRoles;
			showRoleTotpModal = true;
			loading = false;
			return;
		}
		const res = await fetch(`/api/user/uuid/${data.user?.uuid}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify({
				...(displayName !== undefined ? { displayName: displayName.trim() } : {}),
				...(selectedRoles !== undefined ? { roles: selectedRoles } : {}),
				...(roleTotpCode ? { totpcode: roleTotpCode } : {})
			})
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to update display name';
			return;
		}
		showEditModal = false;
		showRoleModal = false;
		data.user!.displayName = displayName || data.user!.displayName;
		if (selectedRoles !== undefined) {
			data.user!.roles = selectedRoles;
		}
		roleTotpCode = '';
		showRoleTotpModal = false;
		pendingRoles = null;
		modalError = '';
	}

	function handleRoleTotpConfirm(value: unknown) {
		if (typeof value === 'string') {
			roleTotpCode = value.trim();
		}
		showRoleTotpModal = false;
		if (!roleTotpCode) return;
		handleUserUpdate(undefined, pendingRoles ?? data.user?.roles ?? []);
	}

	async function handleDeleteAccount() {
		loading = true;
		modalError = '';
		const token = getToken();
		if (totpEnabled && !deleteTotpCode) {
			showDeleteTotpModal = true;
			loading = false;
			return;
		}
		const res = await fetch(`/api/user/uuid/${data.user?.uuid}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${token}`
			},
			body: totpEnabled && deleteTotpCode ? JSON.stringify({ totpcode: deleteTotpCode }) : undefined
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to delete account';
			return;
		}
		showDeleteModal = false;
		showDeleteTotpModal = false;
		deleteTotpCode = '';
		window.location.href = '/';
	}

	function handleTotpConfirm(value: unknown) {
		if (value && typeof value === 'object' && 'enabled' in value) {
			totpEnabled = Boolean((value as { enabled?: boolean }).enabled);
		}
		user.update((u) => (u ? { ...u, totpEnabled } : u));
		showTotpModal = false;
		modalError = '';
	}

	function handleDeleteTotpConfirm(value: unknown) {
		if (typeof value === 'string') {
			deleteTotpCode = value.trim();
		}
		showDeleteTotpModal = false;
		if (!deleteTotpCode) return;
		handleDeleteAccount();
	}

	onMount(() => {
		interval = setInterval(() => {
			now = new Date();
		}, 1000);
		return () => {
			if (interval) clearInterval(interval);
		};
	});
</script>

<svelte:head>
	<title>{data.user?.displayName || data.user?.username} - User Profile</title>

	<meta
		property="og:title"
		content="{data.user?.displayName || data.user?.username} - User Profile"
	/>
	<meta
		property="og:description"
		content="View the profile and {pagination.totalCount !== 0
			? pagination.totalCount
			: ''} paste{pagination.totalCount !== 1 ? 's' : ''} of {data.user?.displayName ||
			data.user?.username} on Sharpbin."
	/>
	<meta property="og:type" content="profile" />
	<meta property="og:url" content={data.url} />
	<meta property="og:site_name" content="Sharpbin" />
	<meta property="profile:username" content={data.user?.username} />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-60px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-5xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="flex items-center justify-center gap-4 text-center text-4xl font-bold">
			{#if data.user?.roles.includes(403)}
				<span
					class="relative flex h-7 w-7 items-center justify-center overflow-hidden rounded-full"
					use:tooltip={roles[403]}
				>
					<User class="h-8 w-8 text-neutral-500" />
					<Ban class="absolute h-7 w-7 text-red-500" />
				</span>
			{:else if data.user?.roles.includes(1) || data.user?.roles.includes(255)}
				{#if data.user?.roles?.length}
					<span use:tooltip={roles[Math.max(...data.user.roles) as keyof typeof roles]}>
						<ShieldUser class="h-8 w-8 text-neutral-400" />
					</span>
				{/if}
			{:else}
				<span use:tooltip={'User'}>
					<User class="h-8 w-8 text-neutral-400" />
				</span>
			{/if}
			<span use:tooltip={data.user?.uuid || 'Unknown UUID'}>
				{data.user?.displayName || data.user?.username}
			</span>
		</h1>
		{#if data.user?.displayName && data.user?.displayName !== data.user?.username}
			<div class="mb-2 flex items-center justify-center">
				<AtSign class="mr-2 inline h-5 w-5 text-neutral-400" />
				<span class="text-neutral-400">{data.user?.username}</span>
			</div>
		{/if}
		<div class="mb-2 flex flex-wrap items-center justify-center gap-4 text-sm">
			<div class="flex shrink-0 items-center">
				<CalendarDays class="mr-2 h-6 w-6 text-neutral-400" />
				<span
					class="text-neutral-400"
					use:tooltip={extractDateFromUUIDv7(data.user?.uuid)?.toLocaleString() ?? 'Unknown'}
				>
					Joined {extractDateFromUUIDv7(data.user?.uuid)?.toLocaleDateString() ?? 'Unknown'}
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
				<span class="text-neutral-400" use:tooltip={`User #${data.user?.uid}`}>
					{data.user?.uid}
				</span>
			</div>
			{#if isOwner && data.user?.lastLogin}
				<div class="flex shrink-0 items-center">
					<Clock class="mr-2 h-6 w-6 text-neutral-400" />
					<span
						class="text-neutral-400"
						use:tooltip={new Date(data.user?.lastLogin).toLocaleString()}
					>
						Last login {dateToRelativeString(new Date(data.user?.lastLogin), true, false, now)}
					</span>
				</div>
			{/if}
		</div>
		{#if isOwner || $user?.roles.some((r) => r === 255 || r === 1)}
			<div class="mt-4 flex flex-wrap justify-center gap-2">
				<button
					on:click={() => {
						showEditModal = true;
						modalError = '';
					}}
					class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
				>
					<Pencil class="h-4 w-4" />
					Edit Display Name
				</button>
				{#if isOwner}
					<button
						on:click={() => {
							showTotpModal = true;
							modalError = '';
						}}
						class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
					>
						<ShieldUser class="h-4 w-4" />
						{totpEnabled ? 'Manage 2FA' : 'Enable 2FA'}
					</button>
				{/if}
				{#if $user?.roles.some((r) => r === 255)}
					<button
						on:click={() => {
							showRoleModal = true;
							modalError = '';
						}}
						class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
					>
						<ShieldUser class="h-4 w-4" />
						Edit Roles
					</button>
				{/if}
				{#if isOwner || $user?.roles.some((r) => r === 255)}
					<button
						on:click={() => {
							showDeleteModal = true;
							modalError = '';
						}}
						class="flex items-center gap-2 rounded bg-red-900 px-4 py-2 text-sm font-medium transition-colors hover:bg-red-800"
					>
						<Trash2 class="h-4 w-4" />
						Delete Account
					</button>
				{/if}
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
				<p class="text-center text-neutral-400">
					{isOwner ? 'You have' : 'This user has'} not created any pastes yet.
				</p>
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
	onConfirm={(value) => handleUserUpdate(value as string)}
	onCancel={() => {
		showEditModal = false;
		modalError = '';
	}}
/>

<Modal
	show={showDeleteModal}
	mode="confirm"
	title="Delete Account"
	message={`This action cannot be undone. ${isOwner ? 'All your' : "This user's"} pastes and account data will be permanently deleted.`}
	confirmButtonText="Delete Account"
	error={modalError}
	onConfirm={() => handleDeleteAccount()}
	onCancel={() => {
		showDeleteModal = false;
		modalError = '';
	}}
/>

<Modal
	show={showDeleteTotpModal}
	mode="totp"
	title="Enter TOTP to delete"
	placeholder="Enter 6-digit code"
	inputType="text"
	error={modalError}
	confirmButtonText="Delete Account"
	onConfirm={(value) => handleDeleteTotpConfirm(value)}
	onCancel={() => {
		showDeleteTotpModal = false;
		deleteTotpCode = '';
		modalError = '';
	}}
/>

<Modal
	show={showRoleModal}
	mode="multiselect"
	title="Edit User Roles"
	items={roleOptions}
	initialValue={data.user?.roles}
	error={modalError}
	onConfirm={(value) => handleUserUpdate(undefined, value as number[])}
	onCancel={() => {
		showRoleModal = false;
		modalError = '';
	}}
/>

<Modal
	show={showTotpModal}
	mode="totpSetup"
	title="Two-Factor Authentication"
	error={modalError}
	totpActive={totpEnabled}
	onConfirm={(value) => handleTotpConfirm(value)}
	onCancel={() => {
		showTotpModal = false;
		modalError = '';
	}}
/>
<Modal
	show={showRoleTotpModal}
	mode="totp"
	title="Admin role requires TOTP"
	placeholder="Enter 6-digit code"
	inputType="text"
	error={modalError}
	confirmButtonText="Continue"
	onConfirm={(value) => handleRoleTotpConfirm(value)}
	onCancel={() => {
		showRoleTotpModal = false;
		roleTotpCode = '';
		pendingRoles = null;
		modalError = '';
	}}
/>

<style>
	button {
		cursor: pointer;
	}
</style>
