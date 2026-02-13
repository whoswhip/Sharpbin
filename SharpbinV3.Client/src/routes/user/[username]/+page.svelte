<script lang="ts">
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { PageData } from './$types';
	import type { Pagination } from '$lib/types/pagination';
	import {
		User,
		CalendarDays,
		ShieldUser,
		Ban,
		AtSign,
		Pencil,
		Trash2,
		Clock,
		Hash,
		Flag,
		LoaderCircle,
		Check,
		X
	} from '@lucide/svelte';
	import {
		extractDateFromUUIDv7,
		tooltip,
		dateToRelativeString,
		extractError
	} from '$lib/utils/misc';
	import { roles } from '$lib/consts';
	import { getToken } from '$lib/utils/auth';
	import { needsAdminTotp } from '$lib/utils/totp';
	import { openModal } from '$lib/stores/modal';
	import { user } from '$lib/stores/user';
	import { onMount } from 'svelte';
	import Paste from '$lib/components/Paste.svelte';
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
	let isEditingDisplayName = false;
	let editDisplayNameValue = '';

	$: isOwner = data.user && $user ? data.user?.uuid === $user.uuid : false;
	$: totpEnabled = Boolean($user?.totpEnabled);
	$: reportsSubmitted = data.reportsSubmitted;
	$: reportsTarget = data.reportsTarget;

	let activeTab: 'pastes' | 'reportsSubmitted' | 'reportsTarget' | 'settings' = isOwner
		? 'settings'
		: 'pastes';

	function updateTab(tab: typeof activeTab) {
		activeTab = tab;
		const url = new URL(page.url);
		url.searchParams.set('tab', tab);
		goto(url, { replaceState: true, noScroll: true, keepFocus: true });
	}

	$: {
		const tab = page.url.searchParams.get('tab');
		switch (tab) {
			case 'reportsSubmitted':
				if (reportsSubmitted) activeTab = 'reportsSubmitted';
				else activeTab = 'pastes';
				break;
			case 'reportsTarget':
				if (reportsTarget) activeTab = 'reportsTarget';
				else activeTab = 'pastes';
				break;
			case 'settings':
				if (isOwner || $user?.roles?.some((r) => r === 255 || r === 1)) activeTab = 'settings';
				else activeTab = 'pastes';
				break;
			default:
				activeTab = 'pastes';
		}
	}

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
			modalError = extractError(err) || 'Failed to update user';
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
			modalError = extractError(err) || 'Failed to delete account';
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

	async function saveDisplayName() {
		const value = editDisplayNameValue.trim();
		if (!value) return;
		await handleUserUpdate(value);
		isEditingDisplayName = false;
	}

	function startEditDisplayName() {
		editDisplayNameValue = data.user?.displayName || data.user?.username || '';
		isEditingDisplayName = true;
	}

	function cancelEditDisplayName() {
		isEditingDisplayName = false;
		editDisplayNameValue = '';
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
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="relative w-[95%] max-w-5xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="flex flex-wrap items-center justify-center gap-4 text-center text-4xl font-bold">
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
			<span
				use:tooltip={data.user?.uuid || 'Unknown UUID'}
				class="max-w-full wrap-break-word whitespace-normal"
			>
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
		{#if !isOwner && !$user?.roles?.some((r) => r === 403)}
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
		<div class="mt-8 flex w-full border-b border-neutral-800">
			{#if isOwner || $user?.roles?.some((r) => r === 255 || r === 1)}
				<button
					class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
					'settings'
						? 'border-neutral-200 text-white'
						: 'border-transparent text-neutral-400'}"
					on:click={() => updateTab('settings')}
				>
					Settings
				</button>
			{/if}
			<button
				class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
				'pastes'
					? 'border-neutral-200 text-white'
					: 'border-transparent text-neutral-400'}"
				on:click={() => updateTab('pastes')}
			>
				Pastes
				<span class="ml-2 rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-300"
					>{pagination.totalCount}</span
				>
			</button>
			{#if reportsSubmitted}
				<button
					class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
					'reportsSubmitted'
						? 'border-neutral-200 text-white'
						: 'border-transparent text-neutral-400'}"
					on:click={() => updateTab('reportsSubmitted')}
				>
					Submitted Reports
					<span class="ml-2 rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-300"
						>{reportsSubmitted.pagination.totalCount}</span
					>
				</button>
			{/if}
			{#if reportsTarget}
				<button
					class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
					'reportsTarget'
						? 'border-neutral-200 text-white'
						: 'border-transparent text-neutral-400'}"
					on:click={() => updateTab('reportsTarget')}
				>
					Reports Against User
					<span class="ml-2 rounded bg-neutral-800 px-2 py-0.5 text-xs text-neutral-300"
						>{reportsTarget.pagination.totalCount}</span
					>
				</button>
			{/if}
		</div>

		<div class="relative mt-4 min-h-50 w-full">
			{#if loading}
				<div
					class="absolute inset-0 z-10 flex items-center justify-center bg-neutral-900/50 backdrop-blur-sm"
				>
					<LoaderCircle class="h-8 w-8 animate-spin text-neutral-200" />
				</div>
			{/if}

			{#if activeTab === 'settings'}
				<div class="grid grid-cols-1 gap-6 md:grid-cols-2">
					<div class="col-span-2">
						<div class="rounded border border-neutral-800 bg-neutral-900/50 p-6">
							<div class="mb-6 flex items-start">
								<div>
									<h2 class="text-xl font-semibold text-neutral-100">Display Name</h2>
									<p class="mt-1 text-sm text-neutral-400">
										{isOwner
											? 'Your display name is shown publicly on your profile and pastes.'
											: "This user's display name is shown publicly on their profile and pastes."}
									</p>
								</div>
							</div>
							<div class="flex items-center justify-between rounded bg-neutral-800/50 p-3">
								{#if isEditingDisplayName}
									<div class="flex w-full items-center gap-2">
										<input
											type="text"
											bind:value={editDisplayNameValue}
											class="w-full bg-transparent px-2 py-1 outline-none font-mono text-neutral-300 border-b border-neutral-600 focus:border-neutral-400"
											maxlength="26"
											on:keydown={(e) => {
												if (e.key === 'Enter') saveDisplayName();
												else if (e.key === 'Escape') cancelEditDisplayName();
											}}
										/>
										<button
											on:click={saveDisplayName}
											class="flex items-center gap-1 rounded bg-green-900/50 px-3 py-2 text-xs font-medium text-green-400 transition-colors hover:bg-green-900"
										>
											<Check class="h-4 w-4" />
											Save
										</button>
										<button
											on:click={cancelEditDisplayName}
											class="flex items-center gap-1 rounded bg-neutral-700 px-3 py-2 text-xs font-medium text-neutral-300 transition-colors hover:bg-neutral-600"
										>
											<X class="h-4 w-4" />
											Cancel
										</button>
									</div>
								{:else}
									<span class="font-mono text-neutral-300"
										>{data.user?.displayName || data.user?.username}</span
									>
									<button
										on:click={startEditDisplayName}
										class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
									>
										<Pencil class="h-4 w-4" />
										Edit
									</button>
								{/if}
							</div>
						</div>
					</div>

					{#if isOwner}
						<div class="col-span-1">
							<div class="h-full rounded border border-neutral-800 bg-neutral-900/50 p-6">
								<div class="mb-6 flex items-start">
									<div>
										<h2 class="text-xl font-semibold text-neutral-100">Security</h2>
										<p class="mt-1 text-sm text-neutral-400">
											Manage your account security settings.
										</p>
									</div>
								</div>

								<div class="space-y-4">
									<div class="flex items-center justify-between rounded bg-neutral-800/50 p-3">
										<div class="flex flex-col">
											<span class="text-sm font-medium text-neutral-200"
												>Two-Factor Authentication</span
											>
											<span class="text-xs text-neutral-500"
												>{totpEnabled ? 'Enabled' : 'Disabled'}</span
											>
										</div>
										<button
											on:click={openTotpSetup}
											class="rounded bg-neutral-700 px-3 py-1.5 text-xs font-medium transition-colors hover:bg-neutral-600"
										>
											{totpEnabled ? 'Manage' : 'Enable'}
										</button>
									</div>
								</div>
							</div>
						</div>
					{/if}

					{#if $user?.roles?.some((r) => r === 255)}
						<div class={isOwner ? 'col-span-1' : 'col-span-2'}>
							<div class="h-full rounded border border-neutral-800 bg-neutral-900/50 p-6">
								<div class="mb-6 flex items-start">
									<div>
										<h2 class="text-xl font-semibold text-neutral-100">Administration</h2>
										<p class="mt-1 text-sm text-neutral-400">Manage user roles and permissions.</p>
									</div>
								</div>
								<div class="space-y-4">
									<div class="flex items-center justify-between rounded bg-neutral-800/50 p-3">
										<div class="flex flex-col">
											<span class="text-sm font-medium text-neutral-200">User Roles</span>
											<span class="text-xs text-neutral-500"
												>{data.user?.roles?.length ?? 0} roles assigned</span
											>
										</div>
										<button
											on:click={openEditRoles}
											class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
										>
											Edit
										</button>
									</div>
								</div>
							</div>
						</div>
					{/if}

					{#if isOwner || $user?.roles?.some((r) => r === 255)}
						<div class="col-span-2">
							<div class="rounded border border-red-900/30 bg-red-900/10 p-6">
								<div class="flex items-start">
									<div>
										<h2 class="text-xl font-semibold text-red-400">Danger Zone</h2>
										<p class="mt-1 text-sm text-red-200/70">
											Irreversible actions related to this account.
										</p>
									</div>
								</div>

								<div class="mt-6 flex items-center justify-between rounded bg-red-900/20 p-4">
									<div>
										<h3 class="font-medium text-red-200">Delete Account</h3>
										<p class="pr-0.5 text-sm text-red-200/60">
											Permanently delete this account and all associated data.
										</p>
									</div>
									<button
										on:click={openDeleteAccount}
										class="rounded border border-red-500/50 bg-red-500/10 px-4 py-2 text-sm font-medium whitespace-nowrap text-red-400 transition-colors hover:bg-red-500 hover:text-white"
									>
										Delete Account
									</button>
								</div>
							</div>
						</div>
					{/if}
				</div>
			{:else if activeTab === 'pastes'}
				<div class="mt-6 max-h-[60vh] space-y-4 overflow-y-auto">
					{#if pastes && pastes.length > 0}
						{#each pastes
							.slice()
							.sort((a, b) => b.uuid.localeCompare(a.uuid)) as paste (paste.uuid)}
							<Paste {paste} {now} showUser={false} compact={true} />
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
			{:else if activeTab === 'reportsSubmitted' && reportsSubmitted && reportsSubmitted.reports.length > 0}
				<div class="mt-6 space-y-3">
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
			{:else if activeTab === 'reportsTarget' && reportsTarget && reportsTarget.reports.length > 0}
				<div class="mt-6 space-y-3">
					{#each reportsTarget.reports as report (report.reportID)}
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
				<p class="mt-6 text-center text-neutral-400">
					{#if activeTab === 'reportsSubmitted'}
						{isOwner ? 'You have' : 'This user has'} not submitted any reports.
					{:else if activeTab === 'reportsTarget'}
						{isOwner ? 'You have' : 'This user has'} not been reported.
					{:else}
						No reports found.
					{/if}
				</p>
			{/if}
		</div>
	</div>
</main>

<style>
	button {
		cursor: pointer;
	}
</style>
