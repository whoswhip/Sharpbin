<script lang="ts">
	import QRCode from 'qrcode';
	import { getRefreshToken, getToken, setTokens } from '$lib/utils/auth';
	import { parseTotpEnabled } from '$lib/utils/totp';
	import { tick } from 'svelte';
	import { extractError } from '$lib/utils/misc';
	import type { ModalItem, ModalMode } from '$lib/types/modal';

	interface Props {
		show?: boolean;
		mode?: ModalMode;
		title?: string;
		message?: string;
		error?: string;
		placeholder?: string;
		inputType?: string;
		inputMaxLength?: number | null;
		items?: ModalItem[];
		initialValue?: unknown;
		totpActive?: boolean | null;
		reportTarget?: 'user' | 'paste' | null;
		reportTargetId?: string | number | null;
		reportSiteKey?: string | null;
		onConfirm: (value: unknown) => void;
		onCancel: () => void;
		confirmButtonText?: string;
	}

	let {
		show = false,
		mode = 'decrypt',
		title = '',
		message = '',
		error = $bindable(''),
		placeholder = '',
		inputType = 'text',
		inputMaxLength = null,
		items = [],
		initialValue = null,
		totpActive = null,
		reportTarget = null,
		reportTargetId = null,
		reportSiteKey = null,
		onConfirm,
		onCancel,
		confirmButtonText = ''
	}: Props = $props();

	let inputValue: string | unknown[] | boolean = $state('');
	let totpSecret = $state('');
	let totpQr = $state('');
	let totpEnabled = $state(false);
	let totpInitialized = $state(false);
	let totpLoading = $state(false);
	let totpError = $state('');
	let displayError = $derived(error || totpError);
	let reportTypes: string[] = $state([]);
	let reportType = $state('');
	let reportInitialized = $state(false);
	let reportLoading = $state(false);
	let multiselectInitialized = $state(false);
	let turnstileEl: HTMLDivElement | null = $state(null);
	let turnstileWidgetId: string | null = null;

	const titleMap = {
		decrypt: 'Enter password to decrypt',
		encrypt: 'Enter password to encrypt',
		confirm: 'Confirm action',
		multiselect: 'Select items',
		totpSetup: 'Set up two-factor authentication',
		totp: 'Enter TOTP code',
		report: 'Create Report',
		prompt: 'Input Required'
	};

	const confirmLabelMap = {
		decrypt: 'Decrypt',
		encrypt: 'Encrypt',
		confirm: 'Confirm',
		multiselect: 'Confirm',
		totpSetup: 'Enable',
		totp: 'Verify',
		report: 'Submit Report',
		prompt: 'Submit'
	};

	function resetModal() {
		inputValue =
			initialValue !== null
				? JSON.parse(JSON.stringify(initialValue))
				: mode === 'multiselect'
					? []
					: '';
		totpSecret = '';
		totpQr = '';
		totpEnabled = false;
		totpInitialized = false;
		totpLoading = false;
		totpError = '';
		reportTypes = [];
		reportType = '';
		reportInitialized = false;
		reportLoading = false;
		multiselectInitialized = false;
		if (turnstileWidgetId && typeof window !== 'undefined' && window.turnstile?.remove) {
			window.turnstile.remove(turnstileWidgetId);
		}
		turnstileEl = null;
		turnstileWidgetId = null;
	}

	function getCodeOrError(message: string) {
		if (typeof inputValue !== 'string') {
			totpError = message;
			return null;
		}
		const code = inputValue.trim();
		if (!code) {
			totpError = message;
			return null;
		}
		return code;
	}

	function onCodeInput(e: Event) {
		if (!(e.target instanceof HTMLInputElement)) return;
		const sanitized = e.target.value.replace(/\D/g, '').slice(0, 6);
		e.target.value = sanitized;
		inputValue = sanitized;
	}

	async function initializeTotp() {
		totpError = '';
		totpLoading = true;
		const token = getToken();
		if (!token) {
			totpError = 'You need to be logged in to manage TOTP.';
			totpLoading = false;
			return;
		}
		if (totpEnabled || parseTotpEnabled(token)) {
			totpEnabled = true;
			totpLoading = false;
			return;
		}
		const res = await fetch('/api/auth/totp/enroll', {
			headers: { Authorization: `Bearer ${token}` }
		});
		if (!res.ok) {
			const data = await res.json().catch(() => null);
			totpError = extractError(data) || 'Failed to start TOTP enrollment.';
			totpLoading = false;
			return;
		}
		const data = await res.json();
		totpSecret = data.secret || '';
		if (data.otpauth) {
			totpQr = await QRCode.toDataURL(data.otpauth, { margin: 1, width: 300 });
		}
		totpLoading = false;
	}

	async function initializeReport() {
		reportLoading = true;
		error = '';
		try {
			const res = await fetch('/api/report/options');
			if (!res.ok) {
				reportLoading = false;
				error = 'Failed to load report options.';
				return;
			}
			const data = (await res.json().catch(() => null)) || {};
			const types = data.types || data.Types || [];
			reportTypes = Array.isArray(types) ? types : [];
			reportType = reportTypes.includes(reportType) ? reportType : reportTypes[0] || '';
			reportLoading = false;
			if (reportSiteKey) {
				await tick();
				renderTurnstile();
			}
		} catch {
			reportLoading = false;
			error = 'Failed to load report options.';
		}
	}

	async function refreshTokens() {
		const token = getToken();
		const refreshToken = getRefreshToken();
		if (!token || !refreshToken) return null;
		console.log('Refreshing tokens after TOTP change...');
		const res = await fetch('/api/auth/refresh', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ token, refreshToken })
		});
		if (!res.ok) return null;
		const data = await res.json();
		if (data.token?.token && data.token?.refreshToken && data.token?.success !== false) {
			setTokens(data.token.token, data.token.refreshToken);
			console.log('Tokens refreshed after TOTP change.');
			return data.token.token as string;
		}
		return null;
	}

	async function handleSubmit(event: Event) {
		event.preventDefault();
		if (mode === 'report') {
			await submitReport();
			return;
		}
		if (mode === 'totp') {
			if (!inputValue || typeof inputValue !== 'string') return;
			onConfirm(inputValue.trim());
			return;
		}
		if (mode === 'totpSetup') {
			await submitTotp();
			return;
		}
		onConfirm(mode === 'confirm' ? true : inputValue);
	}

	function renderTurnstile() {
		if (!reportSiteKey || typeof window === 'undefined') return;
		const mount = () => {
			if (!turnstileEl || !window.turnstile) return;
			if (turnstileWidgetId && window.turnstile.remove) {
				window.turnstile.remove(turnstileWidgetId);
			}
			turnstileWidgetId = window.turnstile.render(turnstileEl, {
				sitekey: reportSiteKey,
				theme: 'dark',
				size: 'flexible',
				appearence: 'interaction-only'
			});
		};
		if (window.turnstile) {
			mount();
			return;
		}
		const existing = document.querySelector('script[data-turnstile="true"]');
		if (!existing) {
			const script = document.createElement('script');
			script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
			script.async = true;
			script.defer = true;
			script.dataset.turnstile = 'true';
			script.onload = () => window.dispatchEvent(new Event('turnstile:loaded'));
			document.body.appendChild(script);
		}
		const handler = () => {
			mount();
			window.removeEventListener('turnstile:loaded', handler);
		};
		window.addEventListener('turnstile:loaded', handler, { once: true });
	}

	async function submitReport() {
		error = '';
		if (!reportTarget || reportTargetId === null) {
			error = 'Missing report target.';
			return;
		}
		if (typeof inputValue !== 'string') inputValue = '';
		const description = inputValue.trim();
		if (!description) {
			error = 'Description is required.';
			return;
		}
		if (description.length < 12) {
			error = 'Description must be at least 12 characters.';
			return;
		}
		if (description.length > 1000) {
			error = 'Description must be 1000 characters or less.';
			return;
		}
		const type = reportType || reportTypes[0] || '';
		if (!type) {
			error = 'Select a report type.';
			return;
		}
		const token = getToken();
		if (!token) {
			error = 'You need to be logged in to report.';
			return;
		}
		const body: Record<string, unknown> = { description, reportType: type };
		if (reportSiteKey) {
			if (typeof window === 'undefined' || !window.turnstile) {
				error = 'Verification unavailable.';
				return;
			}
			const verification = window.turnstile.getResponse();
			if (!verification) {
				error = 'Complete verification.';
				return;
			}
			body.VerificationToken = verification;
		}
		const targetId = encodeURIComponent(String(reportTargetId));
		const reportPath = reportTarget === 'paste' ? 'pastes' : 'users';
		const res = await fetch(`/api/report/${reportPath}/${targetId}/report`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		});
		if (!res.ok) {
			const data = await res.json().catch(() => null);
			error = extractError(data) || 'Failed to submit report.';
			if (reportSiteKey && typeof window !== 'undefined' && window.turnstile) {
				window.turnstile.reset();
			}
			return;
		}
		const data = await res.json().catch(() => null);
		if (reportSiteKey && typeof window !== 'undefined' && window.turnstile) {
			window.turnstile.reset();
		}
		onConfirm(data || { description, reportType: type });
	}

	async function submitTotp() {
		if (totpEnabled) {
			await disableTotp();
			return;
		}
		if (!totpSecret) {
			totpError = 'Missing TOTP secret. Please reopen the modal.';
			return;
		}
		const code = getCodeOrError('Enter the TOTP code from your authenticator app.');
		if (!code) return;
		const token = getToken();
		if (!token) {
			totpError = 'You need to be logged in to enable TOTP.';
			return;
		}
		const res = await fetch('/api/auth/totp/enable', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
			body: JSON.stringify({ secret: totpSecret, code: code })
		});
		if (!res.ok) {
			const data = await res.json().catch(() => null);
			totpError = data?.message || 'Failed to enable TOTP.';
			return;
		}
		const newToken = await refreshTokens();
		totpEnabled = parseTotpEnabled(newToken || getToken());
		onConfirm({ enabled: totpEnabled, secret: totpSecret });
	}

	async function disableTotp() {
		const code = getCodeOrError('Enter the TOTP code to disable two-factor authentication.');
		if (!code) return;
		const token = getToken();
		if (!token) {
			totpError = 'You need to be logged in to disable TOTP.';
			return;
		}
		const res = await fetch('/api/auth/totp/disable', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
			body: JSON.stringify({ code: code })
		});
		if (!res.ok) {
			const data = await res.json().catch(() => null);
			totpError = data?.message || 'Failed to disable TOTP.';
			return;
		}
		const newToken = await refreshTokens();
		totpEnabled = parseTotpEnabled(newToken || getToken());
		onConfirm({ enabled: totpEnabled });
	}

	async function copySecret() {
		if (!totpSecret) return;
		try {
			await navigator.clipboard.writeText(totpSecret);
		} catch {
			return;
		}
	}

	$effect(() => {
		if (!show) resetModal();
	});
	$effect(() => {
		if (show && mode === 'totpSetup' && !totpInitialized) {
			totpInitialized = true;
			if (totpActive !== null) {
				totpEnabled = totpActive;
			}
			initializeTotp();
		}
	});
	$effect(() => {
		if (show && mode === 'report' && !reportInitialized) {
			reportInitialized = true;
			initializeReport();
		}
	});
	$effect(() => {
		if (show && mode === 'multiselect' && !multiselectInitialized) {
			multiselectInitialized = true;
			inputValue = Array.isArray(initialValue) ? JSON.parse(JSON.stringify(initialValue)) : [];
		}
	});
	let displayTitle = $derived(title || titleMap[mode]);
	let confirmLabel = $derived(
		confirmButtonText ||
			(mode === 'totpSetup' ? (totpEnabled ? 'Disable' : 'Enable') : confirmLabelMap[mode])
	);
	let shouldShowInput = $derived(
		mode !== 'confirm' && mode !== 'multiselect' && mode !== 'totpSetup' && mode !== 'report'
	);
</script>

{#if show}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/20 backdrop-blur-xs">
		<form
			onsubmit={handleSubmit}
			class="w-full max-w-md rounded border border-neutral-800 bg-neutral-900 p-6"
		>
			<h2 class="mb-4 text-xl font-semibold text-white">
				{displayTitle}
			</h2>

			{#if message}
				<p class="mb-4 text-neutral-300">
					{message}
				</p>
			{/if}

			{#if mode === 'totpSetup'}
				<div class="mb-4 space-y-3">
					<div
						class="rounded border border-neutral-700 bg-neutral-800 p-3 text-sm text-neutral-200"
					>
						{totpEnabled
							? 'Two-factor authentication is enabled. Enter a current 6-digit code to disable it.'
							: 'Scan the QR code with your authenticator app or copy the secret to add it manually.'}
					</div>
					{#if totpLoading}
						<p class="text-neutral-300">Preparing TOTP enrollment...</p>
					{:else}
						{#if !totpEnabled}
							{#if totpQr}
								<div class="flex justify-center">
									<img
										src={totpQr}
										alt="TOTP QR code"
										class="aspect-square w-full rounded bg-white object-contain p-2"
									/>
								</div>
							{/if}
							{#if totpSecret}
								<div
									class="flex items-center gap-2 rounded border border-neutral-700 bg-neutral-800 p-2"
								>
									<span class="flex-1 truncate font-mono text-sm text-neutral-100"
										>{totpSecret}</span
									>
									<button
										type="button"
										onclick={copySecret}
										class="rounded bg-neutral-700 px-3 py-1 text-sm font-medium text-white transition-colors hover:bg-neutral-800"
									>
										Copy
									</button>
								</div>
							{/if}
						{/if}
						<input
							type="text"
							bind:value={inputValue}
							placeholder="Enter the 6-digit code"
							maxlength="6"
							inputmode="numeric"
							pattern="[0-9]*"
							oninput={onCodeInput}
							class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
						/>
					{/if}
				</div>
			{:else if mode === 'report'}
				<div class="mb-4 space-y-3">
					{#if reportLoading}
						<p class="text-neutral-300">Loading report options...</p>
					{:else}
						{#if reportTypes.length}
							<select
								bind:value={reportType}
								class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
							>
								{#each reportTypes as type, i (i)}
									<option value={type}>{type.replace(/([A-Z])/g, ' $1').trim()}</option>
								{/each}
							</select>
						{/if}
						<textarea
							bind:value={inputValue}
							maxlength={inputMaxLength ?? undefined}
							placeholder={placeholder || 'Describe the issue'}
							class="h-28 w-full resize-none rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
						></textarea>
						{#if reportSiteKey}
							<div class="cf-turnstile w-full" bind:this={turnstileEl}></div>
						{/if}
					{/if}
				</div>
			{:else if shouldShowInput}
				<input
					type={inputType}
					maxlength={inputMaxLength ?? undefined}
					bind:value={inputValue}
					class="mb-3 w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
					{placeholder}
				/>
			{/if}

			{#if mode === 'multiselect'}
				<div
					class="mb-4 max-h-60 overflow-y-auto rounded border border-neutral-700 bg-neutral-800 p-2"
				>
					{#each items as item (item.label)}
						<label
							class="flex cursor-pointer items-center gap-2 rounded p-2 text-white hover:bg-neutral-700"
						>
							<input
								type="checkbox"
								bind:group={inputValue}
								value={item.value}
								class="h-4 w-4 rounded border-neutral-600 bg-neutral-700 text-neutral-500"
							/>
							<span>{item.label}</span>
						</label>
					{/each}
				</div>
			{/if}

			{#if displayError}
				<div class="mb-3 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
					{displayError}
				</div>
			{/if}

			<div class="flex gap-2">
				<button
					type="submit"
					class={`flex-1 cursor-pointer rounded px-4 py-2 font-semibold text-white transition-colors ${
						mode === 'confirm'
							? 'bg-red-900 hover:bg-red-800'
							: 'bg-neutral-700 hover:bg-neutral-800'
					}`}
				>
					{confirmLabel}
				</button>
				<button
					type="button"
					onclick={onCancel}
					class="cursor-pointer rounded border border-neutral-700 px-4 py-2 text-white hover:bg-neutral-950"
				>
					Cancel
				</button>
			</div>
		</form>
	</div>
{/if}
