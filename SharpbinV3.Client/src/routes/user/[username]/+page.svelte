<script lang="ts">
	import { createBubbler, stopPropagation } from 'svelte/legacy';

	const bubble = createBubbler();
	import { resolve } from '$app/paths';
	import { goto, afterNavigate } from '$app/navigation';
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
		KeyRound,
		Trash2,
		Clock,
		Hash,
		Flag,
		LoaderCircle,
		Check,
		X,
		Plus,
		Copy
	} from '@lucide/svelte';
	import {
		extractDateFromUUIDv7,
		tooltip,
		dateToRelativeString,
		extractError
	} from '$lib/utils/misc';
	import { clearTokens, getToken, hasRole, roles } from '$lib/utils/auth';
	import { openModal } from '$lib/stores/modal';
	import { user } from '$lib/stores/user';
	import { onMount } from 'svelte';
	import Paste from '$lib/components/Paste.svelte';
	import { reportStatusLabels, reportTargetLabels, reportTypeLabels } from '$lib/types/report';
	import { fade } from 'svelte/transition';

	interface Props {
		data: PageData;
	}

	let { data }: Props = $props();
	const initialPagination: Pagination = (() => {
		const pagination = data.pastes?.pagination;
		return {
			page: pagination?.page ?? 1,
			pageSize: pagination?.pageSize ?? 50,
			totalCount: pagination?.totalCount ?? 0,
			totalPages: pagination?.totalPages ?? 1
		};
	})();

	let currentPage = $state(initialPagination.page);
	let pagination: Pagination = $state(initialPagination);
	let pastes = $state((() => data.pastes?.pastes ?? [])());
	let loading = $state(false);
	let isOwner = $derived(data.user && $user ? data.user?.uuid === $user.uuid : false);
	let modalError = '';
	let totpEnabled = $derived(Boolean($user?.totpEnabled));
	let now = $state(new Date());
	let interval: ReturnType<typeof setInterval> | null = null;
	let isEditingDisplayName = $state(false);
	let editDisplayNameValue = $state('');
	let isEditingEmail = $state(false);
	let editEmailValue = $state('');
	let emailActionLoading = $state(false);
	let emailMessage = $state('');
	let emailError = $state('');
	let passwordCurrentValue = $state('');
	let passwordNewValue = $state('');
	let passwordConfirmValue = $state('');
	let passwordFocused = $state(false);
	let passwordChecks = $state({
		minLength: false,
		maxLength: false,
		upper: false,
		lower: false,
		number: false
	});
	let passwordValid = $state(false);
	let passwordActionLoading = $state(false);
	let passwordMessage = $state('');
	let passwordError = $state('');
	let passwordResetLinkValue = $state('');
	let passwordResetLinkLoading = $state(false);
	let passwordResetLinkMessage = $state('');
	let passwordResetLinkError = $state('');

	let apiKeys: { uuid: string; name: string; createdAt: string; lastUsedAt: string | null }[] =
		$state([]);
	let successfullyFetchedApiKeys = false;
	let newApiKeyName = $state('');
	let newApiKeyValue = $state('');
	let isCreatingApiKey = $state(false);
	let apiKeyError = $state('');
	let copiedApiKey = $state(false);

	let reportsSubmitted = $derived(data.reportsSubmitted);
	let reportsTarget = $derived(data.reportsTarget);
	let adminsRequire2FA = $derived(
		Boolean(
			(data as unknown as { authOptions?: { admins_require_2fa?: boolean } }).authOptions
				?.admins_require_2fa
		)
	);

	let activeTab: 'pastes' | 'reportsSubmitted' | 'reportsTarget' | 'settings' = $state('pastes');
	let activeSubTab:
		| 'settings:general'
		| 'settings:security'
		| 'settings:admin'
		| 'settings:developer'
		| null = $state(null);

	async function updateTab(
		newPageTab: typeof activeTab,
		newPageSubTab: typeof activeSubTab = null
	) {
		if (activeTab === newPageTab && activeSubTab === newPageSubTab) return;
		activeTab = newPageTab;
		activeSubTab = newPageSubTab;

		const url = new URL(page.url);
		url.searchParams.set('tab', newPageTab);
		if (newPageSubTab) {
			url.searchParams.set('subtab', newPageSubTab);
		} else {
			url.searchParams.delete('subtab');
		}

		// @ts-expect-error - resolve still works even though it's flagged as an error
		// eslint-disable-next-line svelte/no-navigation-without-resolve
		await goto(resolve(url.pathname) + url.search, {
			replaceState: true,
			noScroll: true,
			keepFocus: true,
			invalidateAll: false
		});

		if (
			newPageTab === 'settings' &&
			newPageSubTab === 'settings:developer' &&
			isOwner &&
			apiKeys.length === 0
		) {
			await fetchApiKeys();
		}
	}

	$effect(() => {
		const tab = page.url.searchParams.get('tab');
		const subTab = page.url.searchParams.get('subtab');
		switch (tab) {
			case 'pastes':
				activeTab = 'pastes';
				break;
			case 'reportsSubmitted':
				if (reportsSubmitted) activeTab = 'reportsSubmitted';
				else activeTab = 'pastes';
				break;
			case 'reportsTarget':
				if (reportsTarget) activeTab = 'reportsTarget';
				else activeTab = 'pastes';
				break;
			case 'settings':
				if (isOwner || ($user?.roles && (hasRole($user.roles, 2) || hasRole($user.roles, 4)))) {
					activeTab = 'settings';
				} else activeTab = 'pastes';
				break;
			default:
				if (isOwner) {
					activeTab = 'settings';
				} else {
					activeTab = 'pastes';
				}
		}

		switch (subTab) {
			case 'settings:general':
				activeSubTab = 'settings:general';
				break;
			case 'settings:security':
				activeSubTab = 'settings:security';
				break;
			case 'settings:admin':
				activeSubTab = 'settings:admin';
				break;
			case 'settings:developer':
				activeSubTab = 'settings:developer';
				break;
			default:
				if (activeTab === 'settings' && isOwner) {
					activeSubTab = 'settings:general';
				} else if ($user?.roles && hasRole($user.roles, roles.Admin) && activeTab === 'settings') {
					activeSubTab = 'settings:admin';
				} else {
					activeSubTab = null;
				}
		}
	});

	const roleOptions = [
		{ label: 'Member', value: 1 },
		{ label: 'Moderator', value: 2 },
		{ label: 'Administrator', value: 4 }
	];

	type ActionSecurityRequirements = {
		requiresTotp?: boolean;
		blocked?: boolean;
		message?: string;
	};

	type SecurityAction = 'UpdateRoles' | 'DeleteUser' | 'GeneratePasswordResetLink';

	async function fetchActionSecurityRequirements(action: SecurityAction) {
		const token = getToken();
		if (!token || !data.user?.uuid) {
			return { requiresTotp: false, blocked: false } satisfies ActionSecurityRequirements;
		}

		const res = await fetch(`/api/user/uuid/${data.user.uuid}/requirements?action=${action}`, {
			headers: {
				Authorization: `Bearer ${token}`
			}
		});

		const payload = ((await res.json().catch(() => null)) ?? {}) as ActionSecurityRequirements;
		if (!res.ok) {
			const message = extractError(payload) || 'Failed to check security requirements.';
			throw new Error(message);
		}

		return {
			requiresTotp: Boolean(payload.requiresTotp),
			blocked: Boolean(payload.blocked),
			message: payload.message || ''
		} satisfies ActionSecurityRequirements;
	}

	async function refreshUserInfo() {
		if (!data.user?.uuid) return;
		const token = getToken();
		const res = await fetch(`/api/user/uuid/${data.user.uuid}?page=${currentPage}`, {
			headers: token ? { Authorization: `Bearer ${token}` } : {}
		});
		if (!res.ok) return;
		const json = await res.json().catch(() => null);
		if (!json?.user) return;
		data.user = json.user;
		if (isOwner) {
			user.update((u) =>
				u
					? {
							...u,
							displayName: json.user.displayName ?? u.displayName,
							roles: json.user.roles ?? u.roles,
							isBanned: json.user.isBanned ?? u.isBanned
						}
					: u
			);
		}
	}

	async function promptTotpCode(title: string, confirmButtonText: string) {
		return String(
			await openModal<string>({
				mode: 'totp',
				title,
				placeholder: 'Enter 6-digit code',
				inputType: 'text',
				confirmButtonText,
				cancelValue: ''
			})
		).trim();
	}

	function validatePassword(pw: string) {
		passwordChecks.minLength = pw.length >= 8;
		passwordChecks.maxLength = pw.length <= 128;
		passwordChecks.upper = /[A-Z]/.test(pw);
		passwordChecks.lower = /[a-z]/.test(pw);
		passwordChecks.number = /[0-9]/.test(pw);
		passwordValid =
			passwordChecks.minLength &&
			passwordChecks.maxLength &&
			passwordChecks.upper &&
			passwordChecks.lower &&
			passwordChecks.number;
	}

	$effect(() => {
		validatePassword(passwordNewValue);
	});

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

	async function handleUserUpdate(displayName?: string, selectedRoles?: number, totpcode?: string) {
		loading = true;
		modalError = '';
		const token = getToken();
		const res = await fetch(`/api/user/uuid/${data.user?.uuid}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify({
				...(displayName !== undefined ? { displayName: displayName.trim() } : {}),
				...(selectedRoles !== undefined ? { roles: selectedRoles } : {}),
				...(totpcode?.trim() ? { totpcode: totpcode.trim() } : {})
			})
		});
		loading = false;
		if (!res.ok) {
			loading = false;
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
		try {
			await refreshUserInfo();
		} catch {
			// ignore refresh failures and keep successful update result
		}
		loading = false;
		modalError = '';
	}

	async function changeEmail() {
		const email = editEmailValue.trim();
		if (!email) return;
		let totpcode = '';
		if (totpEnabled) {
			totpcode = await promptTotpCode('TOTP required to change email', 'Continue');
			if (!totpcode) return;
		}
		emailActionLoading = true;
		emailMessage = '';
		emailError = '';
		const token = getToken();
		try {
			const res = await fetch('/api/auth/email/change', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					email,
					...(totpcode ? { totpcode } : {})
				})
			});
			const json = await res.json().catch(() => ({}));
			if (!res.ok) {
				emailError = extractError(json) || 'Failed to send verification email.';
				return;
			}
			emailMessage = json.message || 'Verification email sent.';
			isEditingEmail = false;
			editEmailValue = '';
		} catch {
			emailError = 'Network error';
		} finally {
			emailActionLoading = false;
		}
	}

	async function changePassword() {
		passwordMessage = '';
		passwordError = '';
		const currentPassword = passwordCurrentValue;
		const newPassword = passwordNewValue;
		const confirmPassword = passwordConfirmValue;
		if (!currentPassword || !newPassword || !confirmPassword) {
			passwordError = 'Current password, new password, and confirmation are required.';
			return;
		}
		if (newPassword !== confirmPassword) {
			passwordError = 'New passwords do not match.';
			return;
		}
		if (!passwordValid) {
			passwordError =
				'Password should have at least 8 characters, no more than 128 characters, including uppercase, lowercase, and digits.';
			return;
		}
		let totpcode = '';
		if (totpEnabled || adminsRequire2FA) {
			if (adminsRequire2FA && !totpEnabled) {
				passwordError = '2FA is required to perform this action.';
				return;
			}
			totpcode = await promptTotpCode('TOTP required to change password', 'Continue');
			if (!totpcode) return;
		}
		passwordActionLoading = true;
		const token = getToken();
		try {
			const res = await fetch('/api/auth/password/change', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					currentPassword,
					newPassword,
					...(totpcode ? { totpCode: totpcode } : {})
				})
			});
			const json = await res.json().catch(() => ({}));
			if (!res.ok) {
				passwordError = extractError(json) || 'Failed to change password.';
				return;
			}
			clearTokens();
			window.location.href = '/login';
		} catch {
			passwordError = 'Network error';
		} finally {
			passwordActionLoading = false;
		}
	}

	async function generatePasswordResetLink() {
		passwordResetLinkMessage = '';
		passwordResetLinkError = '';
		const token = getToken();
		if (!token || !data.user?.uuid) return;

		try {
			const requirements = await fetchActionSecurityRequirements('GeneratePasswordResetLink');
			if (requirements.blocked) {
				passwordResetLinkError =
					requirements.message || 'You cannot perform this action right now.';
				return;
			}
			let totpcode = '';
			if (requirements.requiresTotp) {
				totpcode = await promptTotpCode('TOTP required to generate reset link', 'Continue');
				if (!totpcode) return;
			}

			passwordResetLinkLoading = true;
			const res = await fetch(`/api/auth/password/admin-reset-link/${data.user.uuid}`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					...(totpcode ? { totpCode: totpcode } : {})
				})
			});
			const json = await res.json().catch(() => ({}));
			if (!res.ok) {
				passwordResetLinkError = extractError(json) || 'Failed to generate password reset link.';
				return;
			}
			passwordResetLinkValue = json.resetLink || '';
			passwordResetLinkMessage = json.message || 'Password reset link generated.';
		} catch {
			passwordResetLinkError = 'Network error';
		} finally {
			passwordResetLinkLoading = false;
		}
	}

	async function resendVerificationEmail() {
		emailActionLoading = true;
		emailMessage = '';
		emailError = '';
		const token = getToken();
		try {
			const res = await fetch('/api/auth/email/resend-verification', {
				method: 'POST',
				headers: { Authorization: `Bearer ${token}` }
			});
			const json = await res.json().catch(() => ({}));
			if (!res.ok) {
				emailError = extractError(json) || 'Failed to resend verification email.';
				return;
			}
			emailMessage = json.message || 'Verification email sent.';
		} catch {
			emailError = 'Network error';
		} finally {
			emailActionLoading = false;
		}
	}

	function startEditEmail() {
		editEmailValue = data.user?.email || '';
		isEditingEmail = true;
		emailMessage = '';
		emailError = '';
	}

	async function handleDeleteAccount() {
		loading = true;
		modalError = '';
		const token = getToken();
		let totpcode = '';
		let verificationToken = '';
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
		} else if (isOwner && data.user?.emailVerified && data.user?.email) {
			const requestRes = await fetch(`/api/user/uuid/${data.user?.uuid}/delete-verification`, {
				method: 'POST',
				headers: {
					Authorization: `Bearer ${token}`
				}
			});
			if (!requestRes.ok) {
				const err = await requestRes.json().catch(() => ({}));
				loading = false;
				modalError = extractError(err) || 'Failed to send account deletion verification email.';
				await openModal({
					mode: 'confirm',
					title: 'Error',
					message: modalError,
					confirmButtonText: 'OK',
					cancelValue: true
				});
				return;
			}

			verificationToken = String(
				await openModal<string>({
					mode: 'prompt',
					title: 'Verify Account Deletion',
					message: 'Enter the account deletion code sent to your verified email.',
					placeholder: 'Deletion code',
					inputType: 'text',
					confirmButtonText: 'Delete Account',
					cancelValue: ''
				})
			).trim();
			if (!verificationToken) {
				loading = false;
				return;
			}
		}
		const res = await fetch(`/api/user/uuid/${data.user?.uuid}`, {
			method: 'DELETE',
			headers: {
				Authorization: `Bearer ${token}`,
				'Content-Type': 'application/json'
			},
			body:
				totpEnabled && totpcode
					? JSON.stringify({ totpcode })
					: verificationToken
						? JSON.stringify({ token: verificationToken })
						: undefined
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
		if (isOwner) {
			clearTokens();
			user.set(null);
		}
		window.location.href = '/';
	}

	function handleTotpConfirm(value: unknown) {
		let enabled = totpEnabled;
		if (value && typeof value === 'object' && 'enabled' in value) {
			enabled = Boolean((value as { enabled?: boolean }).enabled);
		}
		user.update((u) => (u ? { ...u, totpEnabled: enabled } : u));
		modalError = '';
	}

	async function saveDisplayName() {
		const value = editDisplayNameValue.trim();
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

	async function fetchApiKeys() {
		const token = getToken();
		if (!token) return;
		if (apiKeys.length > 0) return;
		if (successfullyFetchedApiKeys) return;
		loading = true;
		try {
			const res = await fetch('/api/auth/apikey/list', {
				headers: { Authorization: `Bearer ${token}` }
			});
			if (res.ok) {
				const json = await res.json();
				apiKeys = Array.isArray(json.apiKeys) ? json.apiKeys : [];
				successfullyFetchedApiKeys = json.successfullyFetchedApiKeys ?? true;
			}
		} catch (e) {
			console.error('Failed to fetch API keys', e);
		} finally {
			loading = false;
		}
	}

	async function createApiKey() {
		if (!newApiKeyName.trim()) return;
		loading = true;
		apiKeyError = '';
		const token = getToken();
		try {
			const res = await fetch('/api/auth/apikey/create', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`
				},
				body: JSON.stringify({ name: newApiKeyName.trim() })
			});
			const json = await res.json();
			if (res.ok) {
				newApiKeyValue = json.apiKey.key;
				apiKeys = [
					...apiKeys,
					{
						uuid: json.apiKey.uuid,
						name: json.apiKey.name,
						createdAt: json.apiKey.createdAt,
						lastUsedAt: null
					}
				];
				newApiKeyName = '';
				isCreatingApiKey = false;
			} else {
				apiKeyError = json.message || 'Failed to create API key';
			}
		} catch {
			apiKeyError = 'Network error';
		} finally {
			loading = false;
		}
	}

	async function deleteApiKey(uuid: string) {
		const ok = await openModal<boolean>({
			mode: 'confirm',
			title: 'Delete API Key',
			message: 'Are you sure you want to delete this API key? This action cannot be undone.',
			confirmButtonText: 'Delete',
			cancelValue: false
		});
		if (!ok) return;

		loading = true;
		apiKeyError = '';
		const token = getToken();
		try {
			const res = await fetch(`/api/auth/apikey/${uuid}`, {
				method: 'DELETE',
				headers: { Authorization: `Bearer ${token}` }
			});
			if (res.ok) {
				apiKeys = apiKeys.filter((k) => k.uuid !== uuid);
			} else {
				const json = await res.json();
				apiKeyError = json.message || 'Failed to delete API key';
			}
		} catch {
			apiKeyError = 'Network error';
		} finally {
			loading = false;
		}
	}

	async function openEditRoles() {
		const currentRoleBitfield = data.user?.roles ?? 0;
		const selectedValues: number[] = [];
		if (hasRole(currentRoleBitfield, roles.User)) selectedValues.push(roles.User);
		if (hasRole(currentRoleBitfield, roles.Moderator)) selectedValues.push(roles.Moderator);
		if (hasRole(currentRoleBitfield, roles.Admin)) selectedValues.push(roles.Admin);

		const value = await openModal({
			mode: 'multiselect',
			title: 'Edit User Roles',
			items: roleOptions,
			initialValue: selectedValues,
			cancelValue: null
		});
		if (!Array.isArray(value)) return;
		const bitfield = value.reduce((acc, val) => acc | val, 0);

		let totpcode = '';
		try {
			const requirements = await fetchActionSecurityRequirements('UpdateRoles');
			if (requirements.blocked) {
				await openModal({
					mode: 'confirm',
					title: 'Action blocked',
					message: requirements.message || 'You cannot perform this action right now.',
					confirmButtonText: 'OK',
					cancelValue: true
				});
				return;
			}
			if (requirements.requiresTotp) {
				totpcode = await promptTotpCode('TOTP required to update roles', 'Continue');
				if (!totpcode) return;
			}
		} catch (e) {
			await openModal({
				mode: 'confirm',
				title: 'Error',
				message: e instanceof Error ? e.message : 'Failed to check security requirements.',
				confirmButtonText: 'OK',
				cancelValue: true
			});
			return;
		}

		await handleUserUpdate(undefined, bitfield, totpcode);
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
			await refreshUserInfo();
		}
	}

	onMount(() => {
		interval = setInterval(() => {
			now = new Date();
		}, 1000);

		const tab = page.url.searchParams.get('tab');
		if ((tab === 'settings' || !tab) && isOwner) {
			fetchApiKeys();
		}

		return () => {
			if (interval) clearInterval(interval);
		};
	});

	afterNavigate(() => {
		const tab = page.url.searchParams.get('tab');
		if ((tab === 'settings' || !tab) && isOwner && apiKeys.length === 0) {
			fetchApiKeys();
		}
	});

	let reportSiteKey = $derived(
		(data as unknown as { authOptions?: { cf_turnstile_site_key?: string | null } }).authOptions
			?.cf_turnstile_site_key ?? null
	);
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
			{#if data.user?.isBanned}
				<span
					class="relative flex h-7 w-7 items-center justify-center overflow-hidden rounded-full"
					use:tooltip={'Banned'}
				>
					<User class="h-8 w-8 text-neutral-500" />
					<Ban class="absolute h-7 w-7 text-red-500" />
				</span>
			{:else if data.user?.roles && (hasRole(data.user.roles, roles.Admin) || hasRole(data.user.roles, roles.Moderator))}
				<span
					use:tooltip={hasRole(data.user.roles, roles.Admin)
						? 'Admin'
						: hasRole(data.user.roles, roles.Moderator)
							? 'Moderator'
							: 'User'}
				>
					<ShieldUser class="h-8 w-8 text-neutral-400" />
				</span>
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
		{#if !isOwner && !$user?.isBanned && $user && (!hasRole(data.user.roles, roles.Admin) || !hasRole(data.user.roles, roles.Moderator))}
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="absolute top-0 right-0"
				onclick={() =>
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
			{#if isOwner || ($user?.roles && (hasRole($user.roles, roles.Admin) || hasRole($user.roles, roles.Moderator)))}
				<button
					class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
					'settings'
						? 'border-neutral-200 text-white'
						: 'border-transparent text-neutral-400'}"
					onclick={() => updateTab('settings')}
				>
					Settings
				</button>
			{/if}
			<button
				class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeTab ===
				'pastes'
					? 'border-neutral-200 text-white'
					: 'border-transparent text-neutral-400'}"
				onclick={() => updateTab('pastes')}
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
					onclick={() => updateTab('reportsSubmitted')}
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
					onclick={() => updateTab('reportsTarget')}
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
				<div class="absolute inset-0 z-10 flex items-center justify-center bg-neutral-900/50">
					<LoaderCircle class="h-8 w-8 animate-spin text-neutral-200" />
				</div>
			{/if}

			{#if activeTab === 'settings'}
				<div class="-mt-4 mb-4 flex w-full border-b border-neutral-800">
					<button
						class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeSubTab ===
						'settings:general'
							? 'border-neutral-200 text-white'
							: 'border-transparent text-neutral-400'}"
						onclick={() =>
							updateTab(
								'settings',
								activeSubTab === 'settings:general' ? null : 'settings:general'
							)}
					>
						General
					</button>
					{#if isOwner}
						<button
							class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeSubTab ===
							'settings:security'
								? 'border-neutral-200 text-white'
								: 'border-transparent text-neutral-400'}"
							onclick={() =>
								updateTab(
									'settings',
									activeSubTab === 'settings:security' ? null : 'settings:security'
								)}
						>
							Security
						</button>
					{/if}
					{#if $user?.roles && hasRole($user.roles, roles.Admin)}
						<button
							class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeSubTab ===
							'settings:admin'
								? 'border-neutral-200 text-white'
								: 'border-transparent text-neutral-400'}"
							onclick={() =>
								updateTab('settings', activeSubTab === 'settings:admin' ? null : 'settings:admin')}
						>
							Admin
						</button>
					{/if}
					{#if isOwner}
						<button
							class="border-b-2 px-4 py-2 font-medium transition-colors hover:text-white {activeSubTab ===
							'settings:developer'
								? 'border-neutral-200 text-white'
								: 'border-transparent text-neutral-400'}"
							onclick={() =>
								updateTab(
									'settings',
									activeSubTab === 'settings:developer' ? null : 'settings:developer'
								)}
						>
							Developer
						</button>
					{/if}
				</div>
				<div class="grid grid-cols-1 gap-6 md:grid-cols-2">
					{#if activeSubTab === 'settings:general'}
						<div class="col-span-2">
							<h2 class="text-xl font-semibold text-neutral-100">Display Name</h2>
							<p class="mb-1 text-sm text-neutral-400">
								{isOwner
									? 'Your display name is shown publicly on your profile and pastes.'
									: "This user's display name is shown publicly on their profile and pastes."}
							</p>

							<div class="flex items-center justify-between rounded bg-neutral-800/50 p-3">
								{#if isEditingDisplayName}
									<div class="flex w-full items-center gap-2">
										<input
											type="text"
											bind:value={editDisplayNameValue}
											class="w-full border-b border-neutral-600 bg-transparent px-2 py-1 font-mono text-neutral-300 outline-none focus:border-neutral-400"
											maxlength="26"
											onkeydown={(e) => {
												if (e.key === 'Enter') saveDisplayName();
												else if (e.key === 'Escape') cancelEditDisplayName();
											}}
										/>
										<button
											onclick={saveDisplayName}
											class="flex items-center gap-1 rounded bg-green-900/50 px-3 py-2 text-xs font-medium text-green-400 transition-colors hover:bg-green-900"
										>
											<Check class="h-4 w-4" />
											Save
										</button>
										<button
											onclick={cancelEditDisplayName}
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
										onclick={startEditDisplayName}
										class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
									>
										<Pencil class="h-4 w-4" />
										Edit
									</button>
								{/if}
							</div>
						</div>
						{#if isOwner}
							<div class="col-span-2">
								<h2 class="text-xl font-semibold text-neutral-100">Email</h2>
								<p class="mb-1 text-sm text-neutral-400">
									Used for account verification and security notifications.
								</p>

								{#if emailError}
									<div
										class="mb-3 rounded border border-red-900/50 bg-red-900/10 p-3 text-sm text-red-200"
									>
										{emailError}
									</div>
								{/if}
								{#if emailMessage}
									<div
										class="mb-3 rounded border border-green-900/50 bg-green-900/10 p-3 text-sm text-green-200"
									>
										{emailMessage}
									</div>
								{/if}

								<div class="rounded bg-neutral-800/50 p-3">
									{#if isEditingEmail}
										<div class="flex flex-col gap-3 sm:flex-row sm:items-center">
											<input
												type="email"
												bind:value={editEmailValue}
												placeholder="you@example.com"
												class="w-full border-b border-neutral-600 bg-transparent px-2 py-1 font-mono text-neutral-300 outline-none focus:border-neutral-400"
												autocomplete="email"
												onkeydown={(e) => {
													if (e.key === 'Enter') changeEmail();
													else if (e.key === 'Escape') {
														isEditingEmail = false;
														editEmailValue = '';
													}
												}}
											/>
											<div class="flex shrink-0 gap-2">
												<button
													onclick={changeEmail}
													disabled={emailActionLoading || !editEmailValue.trim()}
													class="flex items-center gap-1 rounded bg-green-900/50 px-3 py-2 text-xs font-medium text-green-400 transition-colors hover:bg-green-900 disabled:opacity-50"
												>
													{#if emailActionLoading}
														<LoaderCircle class="h-4 w-4 animate-spin" />
													{:else}
														<Check class="h-4 w-4" />
													{/if}
													Send verification
												</button>
												<button
													onclick={() => {
														isEditingEmail = false;
														editEmailValue = '';
													}}
													class="flex items-center gap-1 rounded bg-neutral-700 px-3 py-2 text-xs font-medium text-neutral-300 transition-colors hover:bg-neutral-600"
												>
													<X class="h-4 w-4" />
													Cancel
												</button>
											</div>
										</div>
									{:else}
										<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
											<div class="flex min-w-0 flex-col gap-1">
												<span class="font-mono break-all text-neutral-300">
													{data.user?.email || 'No email set'}
												</span>
												<span
													class="text-sm {data.user?.emailVerified
														? 'text-green-400'
														: 'text-amber-400'}"
												>
													{data.user?.email
														? data.user?.emailVerified
															? 'Verified'
															: 'Not verified'
														: 'Add an email to enable verification'}
												</span>
											</div>
											<div class="flex flex-wrap gap-2">
												{#if data.user?.email && !data.user?.emailVerified}
													<button
														onclick={resendVerificationEmail}
														disabled={emailActionLoading}
														class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-50"
													>
														{#if emailActionLoading}
															<LoaderCircle class="h-4 w-4 animate-spin" />
														{:else}
															<Check class="h-4 w-4" />
														{/if}
														Resend
													</button>
												{/if}
												<button
													onclick={startEditEmail}
													disabled={emailActionLoading}
													class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-50"
												>
													<Pencil class="h-4 w-4" />
													{data.user?.email ? 'Change' : 'Add'}
												</button>
											</div>
										</div>
									{/if}
								</div>
							</div>
						{/if}
					{:else if isOwner && activeSubTab === 'settings:security'}
						<div class="col-span-2">
							<div class="space-y-4">
								<div class="flex items-center justify-between rounded bg-neutral-800/50 p-4">
									<div class="flex flex-col">
										<span class=" font-medium text-neutral-200">Two-Factor Authentication</span>
										<span class="text-sm text-neutral-500"
											>{totpEnabled ? 'Enabled' : 'Disabled'}</span
										>
									</div>
									<button
										onclick={openTotpSetup}
										class="rounded bg-neutral-700 px-3 py-1.5 text-sm font-medium transition-colors hover:bg-neutral-600"
									>
										{totpEnabled ? 'Manage' : 'Enable'}
									</button>
								</div>
								<div class="rounded bg-neutral-800/50 p-4">
									<div class="mb-3 flex flex-col gap-1">
										<span class="font-medium text-neutral-200">Change Password</span>
										<span class="text-sm text-neutral-500">
											Use your current password and choose a new one.
										</span>
									</div>

									{#if passwordError}
										<div
											class="mb-3 rounded border border-red-900/50 bg-red-900/10 p-3 text-sm text-red-200"
										>
											{passwordError}
										</div>
									{/if}
									{#if passwordMessage}
										<div
											class="mb-3 rounded border border-green-900/50 bg-green-900/10 p-3 text-sm text-green-200"
										>
											{passwordMessage}
										</div>
									{/if}

									<div class="grid gap-3">
										<input
											type="password"
											bind:value={passwordCurrentValue}
											placeholder="Current password"
											autocomplete="current-password"
											class="w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-200 transition-colors outline-none focus:border-neutral-500"
										/>
										<input
											type="password"
											bind:value={passwordNewValue}
											placeholder="New password"
											autocomplete="new-password"
											onfocus={() => (passwordFocused = true)}
											onblur={() => (passwordFocused = false)}
											class="w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-200 transition-colors outline-none focus:border-neutral-500"
										/>
										{#if passwordFocused}
											<ul
												transition:fade
												class="space-y-2 rounded border border-neutral-700 bg-neutral-800 p-3 text-sm"
											>
												<li
													class="flex items-center gap-2 {passwordChecks.minLength
														? 'text-green-400'
														: 'text-red-400'}"
												>
													{#if passwordChecks.minLength}
														<Check class="h-4 w-4" />
													{:else}
														<X class="h-4 w-4" />
													{/if}
													At least 8 characters
												</li>
												<li
													class="flex items-center gap-2 {passwordChecks.maxLength
														? 'text-green-400'
														: 'text-red-400'}"
												>
													{#if passwordChecks.maxLength}
														<Check class="h-4 w-4" />
													{:else}
														<X class="h-4 w-4" />
													{/if}
													No more than 128 characters
												</li>
												<li
													class="flex items-center gap-2 {passwordChecks.upper
														? 'text-green-400'
														: 'text-red-400'}"
												>
													{#if passwordChecks.upper}
														<Check class="h-4 w-4" />
													{:else}
														<X class="h-4 w-4" />
													{/if}
													At least one uppercase letter
												</li>
												<li
													class="flex items-center gap-2 {passwordChecks.lower
														? 'text-green-400'
														: 'text-red-400'}"
												>
													{#if passwordChecks.lower}
														<Check class="h-4 w-4" />
													{:else}
														<X class="h-4 w-4" />
													{/if}
													At least one lowercase letter
												</li>
												<li
													class="flex items-center gap-2 {passwordChecks.number
														? 'text-green-400'
														: 'text-red-400'}"
												>
													{#if passwordChecks.number}
														<Check class="h-4 w-4" />
													{:else}
														<X class="h-4 w-4" />
													{/if}
													At least one number
												</li>
											</ul>
										{/if}
										<input
											type="password"
											bind:value={passwordConfirmValue}
											placeholder="Confirm new password"
											autocomplete="new-password"
											class="w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-neutral-200 transition-colors outline-none focus:border-neutral-500"
										/>
										<div class="flex items-center justify-end">
											<button
												onclick={changePassword}
												disabled={passwordActionLoading ||
													!passwordValid ||
													passwordNewValue !== passwordConfirmValue}
												class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-50"
											>
												{#if passwordActionLoading}
													<LoaderCircle class="h-4 w-4 animate-spin" />
												{:else}
													<KeyRound class="h-4 w-4" />
												{/if}
												Change Password
											</button>
										</div>
									</div>
								</div>
							</div>
						</div>
						{#if isOwner}
							<div class="col-span-2">
								<div class="flex items-center justify-between rounded bg-red-900/20 p-4">
									<div>
										<h3 class="font-medium text-red-200">Delete Account</h3>
										<p class="pr-0.5 text-sm text-red-200/60">
											Permanently delete this account and all associated data.
										</p>
									</div>
									<button
										onclick={openDeleteAccount}
										class="rounded border border-red-500/50 bg-red-500/10 px-4 py-2 text-sm font-medium whitespace-nowrap text-red-400 transition-colors hover:bg-red-500 hover:text-white"
									>
										Delete Account
									</button>
								</div>
							</div>
						{/if}
					{:else if $user?.roles && hasRole($user.roles, roles.Admin) && activeSubTab === 'settings:admin'}
						<div class="col-span-2">
							<div class="space-y-4">
								<div class="flex items-center justify-between rounded bg-neutral-800/50 p-4">
									<div class="flex flex-col">
										<span class="font-medium text-neutral-200">User Roles</span>
										<span class="text-sm text-neutral-500"
											>{(() => {
												let count = 0;
												if (data.user?.roles) {
													if (hasRole(data.user.roles, roles.User)) count++;
													if (hasRole(data.user.roles, roles.Moderator)) count++;
													if (hasRole(data.user.roles, roles.Admin)) count++;
												}
												return count;
											})()} roles assigned</span
										>
									</div>
									<button
										onclick={openEditRoles}
										class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
									>
										<Pencil class="h-4 w-4" />

										Edit
									</button>
								</div>
								<div class="rounded bg-neutral-800/50 p-4">
									<div class="flex justify-between gap-1">
										<div class="flex flex-col">
											<span class="font-medium text-neutral-200">Password Reset Link</span>
											<span class="text-sm text-neutral-500">
												Send the user a reset link or copy one for manual delivery.
											</span>
										</div>
										<div class="flex items-center justify-end">
											<button
												onclick={generatePasswordResetLink}
												disabled={passwordResetLinkLoading}
												class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-50"
											>
												{#if passwordResetLinkLoading}
													<LoaderCircle class="h-4 w-4 animate-spin" />
												{:else}
													<KeyRound class="h-4 w-4" />
												{/if}
												Generate Reset Link
											</button>
										</div>
									</div>

									{#if passwordResetLinkError}
										<div
											class="mt-3 rounded border border-red-900/50 bg-red-900/10 p-3 text-sm text-red-200"
										>
											{passwordResetLinkError}
										</div>
									{/if}
									{#if passwordResetLinkMessage}
										<div
											class="mt-3 rounded border border-green-900/50 bg-green-900/10 p-3 text-sm text-green-200"
										>
											{passwordResetLinkMessage}
										</div>
									{/if}

									{#if passwordResetLinkValue}
										<div class="mt-3 flex items-center gap-2 rounded bg-neutral-900/70 p-2">
											<code class="flex-1 font-mono text-sm break-all text-green-300"
												>{passwordResetLinkValue}</code
											>
											<button
												class="p-1 text-neutral-400 hover:text-white"
												onclick={() => {
													navigator.clipboard.writeText(passwordResetLinkValue);
												}}
												use:tooltip={'Copy reset link'}
											>
												<Copy class="h-4 w-4" />
											</button>
										</div>
									{/if}
								</div>
							</div>
						</div>
						{#if !isOwner && data.user?.roles && !hasRole(data.user.roles, roles.Admin)}
							<div class="col-span-2">
								<div class="flex items-center justify-between rounded bg-red-900/20 p-4">
									<div>
										<h3 class="font-medium text-red-200">Delete Account</h3>
										<p class="pr-0.5 text-sm text-red-200/60">
											Permanently delete this account and all associated data.
										</p>
									</div>
									<button
										onclick={openDeleteAccount}
										class="rounded border border-red-500/50 bg-red-500/10 px-4 py-2 text-sm font-medium whitespace-nowrap text-red-400 transition-colors hover:bg-red-500 hover:text-white"
									>
										Delete Account
									</button>
								</div>
							</div>
						{/if}
					{:else if isOwner && activeSubTab === 'settings:developer'}
						<div class="col-span-2">
							<div class="mb-2 flex flex-col items-start justify-between">
								<h2 class="text-xl font-semibold text-neutral-100">
									API Keys ({apiKeys.length}/10)
								</h2>
								<p class="text-sm text-neutral-400">
									Manage API keys for accessing Sharpbin programmatically.
								</p>
							</div>

							{#if apiKeyError}
								<div
									class="mb-4 rounded border border-red-900/50 bg-red-900/10 p-3 text-sm text-red-200"
								>
									{apiKeyError}
								</div>
							{/if}

							<div class="mb-6">
								{#if isCreatingApiKey}
									<div class="flex items-center gap-2">
										<input
											type="text"
											placeholder="Key Name"
											bind:value={newApiKeyName}
											class="flex-1 border-b border-neutral-600 bg-transparent px-3 py-2 font-mono text-neutral-300 outline-none focus:border-neutral-400"
											maxlength="26"
										/>
										<button
											onclick={createApiKey}
											disabled={loading || !newApiKeyName}
											class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-50"
										>
											{#if loading}
												<LoaderCircle class="h-4 w-4 animate-spin" />
											{:else}
												<Plus class="h-4 w-4" />
											{/if}
											Create
										</button>
										<button
											onclick={() => {
												isCreatingApiKey = false;
												newApiKeyName = '';
											}}
											class="flex items-center gap-2 rounded bg-neutral-800 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-700"
										>
											Cancel
										</button>
									</div>
								{:else}
									<button
										onclick={() => (isCreatingApiKey = true)}
										class="flex items-center gap-2 rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600"
									>
										<Plus class="h-4 w-4" />
										Create New Key
									</button>
								{/if}
							</div>

							{#if newApiKeyValue}
								<div class="mb-6 rounded border border-green-900/50 bg-green-900/10 p-4">
									<div class="mb-2 flex items-center justify-between">
										<span class="text-sm font-medium text-green-400">API Key Created</span>
										<button
											onclick={() => (newApiKeyValue = '')}
											class="text-green-400/70 hover:text-green-400"
										>
											<X class="h-4 w-4" />
										</button>
									</div>
									<p class="mb-3 text-xs text-green-200/70">
										Please copy your API key now. You won't be able to see it again.
									</p>
									<div class="flex items-center gap-2 rounded bg-neutral-900/50 p-2">
										<code class="flex-1 font-mono text-sm break-all text-green-300"
											>{newApiKeyValue}</code
										>
										<button
											class="p-1 text-neutral-400 hover:text-white"
											onclick={() => {
												navigator.clipboard.writeText(newApiKeyValue);
												copiedApiKey = true;
												setTimeout(() => (copiedApiKey = false), 1000);
											}}
											use:tooltip={'Copy to clipboard'}
										>
											<div class="relative mr-1 h-5 w-5">
												{#if copiedApiKey}
													<span
														transition:fade={{ duration: 200 }}
														class="absolute inset-0 flex items-center justify-center"
														><Check class="h-4 w-4 text-green-400" /></span
													>
												{:else}
													<span
														transition:fade={{ duration: 200 }}
														class="absolute inset-0 flex items-center justify-center"
														><Copy class="h-4 w-4 text-neutral-400" /></span
													>
												{/if}
											</div>
										</button>
									</div>
								</div>
							{/if}

							<div class="space-y-2">
								{#if apiKeys.length !== 0}
									{#each apiKeys as key (key.uuid)}
										<div class="flex items-center justify-between rounded bg-neutral-800/50 p-3">
											<div class="flex flex-col gap-1">
												<span class="font-medium text-neutral-200">{key.name}</span>
												<div class="flex gap-3 text-xs text-neutral-500">
													<span>Created: {new Date(key.createdAt).toLocaleDateString()}</span>
													<span
														>Last used: {key.lastUsedAt
															? dateToRelativeString(new Date(key.lastUsedAt), true, false, now)
															: 'Never'}</span
													>
												</div>
											</div>
											<button
												onclick={() => deleteApiKey(key.uuid)}
												disabled={loading}
												class="p-2 text-neutral-500 transition-colors hover:text-red-400"
												title="Revoke Key"
											>
												<Trash2 class="h-4 w-4" />
											</button>
										</div>
									{/each}
								{/if}
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
							onclick={() => fetchPage(currentPage - 1)}
							disabled={currentPage === 1 || loading}
						>
							Prev
						</button>
						<span class="text-neutral-400">
							Page {currentPage} of {pagination.totalPages}
						</span>
						<button
							class="rounded bg-neutral-700 px-3 py-1 disabled:opacity-50"
							onclick={() => fetchPage(currentPage + 1)}
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
							onclick={() => goto(resolve(`/report/${report.reportID}`))}
							onkeydown={(e) => {
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
										onclick={stopPropagation(bubble('click'))}
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
											onclick={stopPropagation(bubble('click'))}
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
							onclick={() => goto(resolve(`/report/${report.reportID}`))}
							onkeydown={(e) => {
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
										onclick={stopPropagation(bubble('click'))}
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
										onclick={stopPropagation(bubble('click'))}
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
											onclick={stopPropagation(bubble('click'))}
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
