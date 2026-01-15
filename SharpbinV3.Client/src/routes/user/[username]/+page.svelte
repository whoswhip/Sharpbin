<script lang="ts">
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
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
		Hash,
		Flag
	} from '@lucide/svelte';
	import { extractDateFromUUIDv7, tooltip, dateToRelativeString } from '$lib/utils/misc';
	import { roles } from '$lib/consts';
	import { getToken } from '$lib/utils/auth';
	import { needsAdminTotp } from '$lib/utils/totp';
	import { openModal } from '$lib/stores/modal';
	import { user } from '$lib/stores/user';
	import { onMount } from 'svelte';
	import { reportStatusLabels, reportTargetLabels, reportTypeLabels } from '$lib/types/report';

	export let data: PageData;


	let currentPage = data.pastes?.pagination?.page ?? 1;
	let pagination: Pagination = data.pastes?.pagination ?? {
		page: 1,
		pageSize: 50,
		totalCount: 0,
		totalPages: 1
	};
	let pastes = data.pastes?.pastes ?? [];
	let loading = false;
	let isOwner = false;
	let modalError = '';
	let totpEnabled = false;
	let now = new Date();
	let interval: ReturnType<typeof setInterval> | null = null;

	$: isOwner = data.user && $user ? data.user?.uuid === $user.uuid : false;
	$: totpEnabled = Boolean($user?.totpEnabled);
	$: reportsSubmitted = data.reportsSubmitted;
	$: reportsTarget = data.reportsTarget;

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
		let totpcode = '';
		if (needsAdminTotp(totpEnabled, currentRoles, nextRoles)) {
			totpcode = String(
				await openModal<string>({
					mode: 'totp',
					title: 'Admin role requires TOTP',
					placeholder: 'Enter 6-digit code',
					inputType: 'text',
					confirmButtonText: 'Continue',
					cancelValue: ''
				})
			).trim();
			if (!totpcode) {
				loading = false;
				return;
			}
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
				...(totpcode ? { totpcode } : {})
			})
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to update display name';
			await openModal({
				mode: 'confirm',
				title: 'Error',
				message: modalError,
				confirmButtonText: 'OK',
				cancelValue: true
			});
			return;
		}
		data.user!.displayName = displayName || data.user!.displayName;
		if (selectedRoles !== undefined) {
			data.user!.roles = selectedRoles;
		}
		modalError = '';
	}

	async function handleDeleteAccount() {
		loading = true;
		modalError = '';
		const token = getToken();
		let totpcode = '';
		if (totpEnabled) {
			totpcode = String(
				await openModal<string>({
					mode: 'totp',
					title: 'Enter TOTP to delete',
					placeholder: 'Enter 6-digit code',
					inputType: 'text',
					confirmButtonText: 'Delete Account',
					cancelValue: ''
				})
			).trim();
			if (!totpcode) {
				loading = false;
				return;
			}
		}
		const res = await fetch(`/api/user/uuid/${data.user?.uuid}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${token}`
			},
			body: totpEnabled && totpcode ? JSON.stringify({ totpcode }) : undefined
		});
		loading = false;
		if (!res.ok) {
			const err = await res.json();
			modalError = err.message || 'Failed to delete account';
			await openModal({
				mode: 'confirm',
				title: 'Error',
				message: modalError,
				confirmButtonText: 'OK',
				cancelValue: true
			});
			return;
		}
		window.location.href = '/';
	}

	function handleTotpConfirm(value: unknown) {
		if (value && typeof value === 'object' && 'enabled' in value) {
			totpEnabled = Boolean((value as { enabled?: boolean }).enabled);
		}
		user.update((u) => (u ? { ...u, totpEnabled } : u));
		modalError = '';
	}

	async function openEditDisplayName() {
		const value = String(
			await openModal<string>({
				mode: 'prompt',
				title: 'Edit Display Name',
				placeholder: 'New Display Name',
				error: modalError,
				cancelValue: ''
			})
		).trim();
		if (!value) return;
		await handleUserUpdate(value);
	}

	async function openEditRoles() {
		const value = await openModal({
			mode: 'multiselect',
			title: 'Edit User Roles',
			items: roleOptions,
			initialValue: data.user?.roles,
			cancelValue: null
		});
		if (!Array.isArray(value)) return;
		await handleUserUpdate(undefined, value as number[]);
	}

	async function openDeleteAccount() {
		const ok = await openModal<boolean>({
			mode: 'confirm',
			title: 'Delete Account',
			message: `This action cannot be undone. ${isOwner ? 'All your' : "This user's"} pastes and account data will be permanently deleted.`,
			confirmButtonText: 'Delete Account',
			cancelValue: false
		});
		if (!ok) return;
		await handleDeleteAccount();
	}

	async function openTotpSetup() {
		const result = await openModal({
			mode: 'totpSetup',
			title: 'Two-Factor Authentication',
			totpActive: totpEnabled,
			cancelValue: null
		});
		if (result) {
			handleTotpConfirm(result);
		}
	}

	onMount(() => {
		interval = setInterval(() => {
			now = new Date();
		}, 1000);
		return () => {
			if (interval) clearInterval(interval);
		};
	});

	$: reportSiteKey =
		(data as unknown as { authOptions?: { cf_turnstile_site_key?: string | null } }).authOptions
			?.cf_turnstile_site_key ?? null;
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
	<div class="relative w-[95%] max-w-5xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="flex items-center justify-center gap-4 text-center text-4xl font-bold">
			{#if data.user?.roles?.includes(403)}
				<span
					class="relative flex h-7 w-7 items-center justify-center overflow-hidden rounded-full"
					use:tooltip={roles[403]}
				>
					<User class="h-8 w-8 text-neutral-500" />
					<Ban class="absolute h-7 w-7 text-red-500" />
				</span>
			{:else if data.user?.roles?.includes(1) || data.user?.roles?.includes(255)}
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
			{#if reportsSubmitted}
				<div class="flex shrink-0 items-center">
					<Flag class="mr-2 h-6 w-6 text-neutral-400" />
					<span class="text-neutral-400"
						>{reportsSubmitted.pagination.totalCount} submitted report{reportsSubmitted.pagination
							.totalCount !== 1
							? 's'
							: ''}</span
					>
				</div>
			{/if}
			{#if reportsTarget}
				<div class="flex shrink-0 items-center">
					<Flag class="mr-2 h-6 w-6 text-neutral-400" />
					<span class="text-neutral-400"
						>{reportsTarget.pagination.totalCount} report{reportsTarget.pagination.totalCount !== 1
							? 's'
							: ''}</span
					>
				</div>
			{/if}
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
		{#if !isOwner || !$user?.roles?.some((r) => r === 403)}
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="absolute top-0 right-0"
				on:click={() =>
					openModal({
						mode: 'report',
						title: 'Report User',
						reportTarget: 'user',
						reportTargetId: data.user?.uuid || '',
						reportSiteKey: reportSiteKey,
						confirmButtonText: 'Submit Report',
						cancelValue: null
					})}
			>
				<Flag class="m-4 h-6 w-6 cursor-pointer text-neutral-400 hover:text-amber-400" />
			</div>
		{/if}
		{#if isOwner || $user?.roles?.some((r) => r === 255 || r === 1)}
			<div class="mt-4 flex flex-wrap justify-center gap-2">
				<button
					on:click={openEditDisplayName}
					class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
				>
					<Pencil class="h-4 w-4" />
					Edit Display Name
				</button>
				{#if isOwner}
					<button
						on:click={openTotpSetup}
						class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
					>
						<ShieldUser class="h-4 w-4" />
						{totpEnabled ? 'Manage 2FA' : 'Enable 2FA'}
					</button>
				{/if}
				{#if $user?.roles?.some((r) => r === 255)}
					<button
						on:click={openEditRoles}
						class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
					>
						<ShieldUser class="h-4 w-4" />
						Edit Roles
					</button>
				{/if}
				{#if isOwner || $user?.roles?.some((r) => r === 255)}
					<button
						on:click={openDeleteAccount}
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
		{#if reportsSubmitted || reportsTarget}
			<div class="mt-6 space-y-6">
				{#if reportsSubmitted}
					<div class="rounded border border-neutral-800 bg-neutral-900/60 p-4">
						<h2 class="mb-3 text-xl font-semibold text-neutral-200">Submitted Reports</h2>
						{#if reportsSubmitted.reports.length > 0}
							<div class="space-y-3">
								{#each reportsSubmitted.reports as report (report.reportID)}
									<div
										class="flex cursor-pointer flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
										role="link"
										tabindex="0"
										on:click={() => goto(resolve(`/report/${report.reportID}`))}
										on:keydown={(e) => {
											if (e.key === 'Enter' || e.key === ' ') {
												e.preventDefault();
												goto(resolve(`/report/${report.reportID}`));
											}
										}}
									>
										<div class="flex flex-wrap items-center justify-between gap-2">
											<span class="text-lg font-semibold text-neutral-100">
												Report #{report.reportID}
											</span>
											<span class="text-sm text-neutral-300">
												{reportTypeLabels[report.type] ?? 'Other'}
												· {reportStatusLabels[report.status] ?? 'Open'}
											</span>
										</div>
										<div class="flex flex-wrap items-center gap-3 text-sm text-neutral-400">
											<span>{reportTargetLabels[report.targetType] ?? 'Unknown'}</span>
											{#if report.pasteId}
												<a
													href={resolve(`/${report.pasteId}`)}
													class="text-neutral-300 hover:text-white"
													on:click|stopPropagation
												>
													{report.pasteTitle !== '' ? report.pasteTitle : report.pasteId}
												</a>
											{/if}
											{#if report.userUUID}
												{#if report.targetUsername}
													<a
														href={resolve(`/user/${report.targetUsername}`)}
														class="text-neutral-300 hover:text-white"
														use:tooltip={report.userUUID}
														on:click|stopPropagation
													>
														{report.targetDisplayName || report.targetUsername}
													</a>
												{:else}
													<span>{report.userUUID}</span>
												{/if}
											{/if}
											<span>
												Created {new Date(report.createdAt * 1000).toLocaleString()}
											</span>
										</div>
										{#if report.description}
											<p class="text-sm text-neutral-300">{report.description}</p>
										{/if}
									</div>
								{/each}
							</div>
						{:else}
							<p class="text-center text-neutral-400">No submitted reports to show.</p>
						{/if}
					</div>
				{/if}
				{#if reportsTarget}
					<div class="rounded border border-neutral-800 bg-neutral-900/60 p-4">
						<h2 class="mb-3 text-xl font-semibold text-neutral-200">Reports About This User</h2>
						{#if reportsTarget.reports.length > 0}
							<div class="space-y-3">
								{#each reportsTarget.reports as report (report.reportID)}
									<div
										class="flex flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
										role="link"
										tabindex="0"
										on:click={() => goto(resolve(`/report/${report.reportID}`))}
										on:keydown={(e) => {
											if (e.key === 'Enter' || e.key === ' ') {
												e.preventDefault();
												goto(resolve(`/report/${report.reportID}`));
											}
										}}
									>
										<div class="flex flex-wrap items-center justify-between gap-2">
											<span class="text-lg font-semibold text-neutral-100">
												Report #{report.reportID}
											</span>
											<span class="text-sm text-neutral-300">
												{reportTypeLabels[report.type] ?? 'Other'}
												· {reportStatusLabels[report.status] ?? 'Open'}
											</span>
										</div>
										<div class="flex flex-wrap items-center gap-3 text-sm text-neutral-400">
											<span>{reportTargetLabels[report.targetType] ?? 'Unknown'}</span>
											{#if report.reporterUsername}
												<a
													href={resolve(`/user/${report.reporterUsername}`)}
													class="text-neutral-300 hover:text-white"
													use:tooltip={report.reporterUUID}
													on:click|stopPropagation
												>
													{report.reporterDisplayName || report.reporterUsername}
												</a>
											{:else}
												<span>{report.reporterUUID}</span>
											{/if}
											{#if report.pastePID}
												<a
													href={resolve(`/${report.pasteId ?? report.pastePID}`)}
													class="text-neutral-300 hover:text-white"
													on:click|stopPropagation
												>
													{report.pasteTitle ? report.pasteTitle : `Paste #${report.pastePID}`}
												</a>
											{/if}
											{#if report.userUUID}
												{#if report.targetUsername}
													<a
														href={resolve(`/user/${report.targetUsername}`)}
														class="text-neutral-300 hover:text-white"
														use:tooltip={report.userUUID}
														on:click|stopPropagation
													>
														{report.targetDisplayName || report.targetUsername}
													</a>
												{:else}
													<span>{report.userUUID}</span>
												{/if}
											{/if}
											<span>
												Created {new Date(report.createdAt * 1000).toLocaleString()}
											</span>
										</div>
										{#if report.description}
											<p class="text-sm text-neutral-300">{report.description}</p>
										{/if}
									</div>
								{/each}
							</div>
						{:else}
							<p class="text-center text-neutral-400">No reports to show.</p>
						{/if}
					</div>
				{/if}
			</div>
		{/if}
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

<style>
	button {
		cursor: pointer;
	}
</style>
