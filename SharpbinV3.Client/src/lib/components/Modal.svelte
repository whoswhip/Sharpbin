<script lang="ts">
	import QRCode from 'qrcode';
	import { getRefreshToken, getToken, setTokens } from '$lib/utils/auth';
	import { parseTotpEnabled } from '$lib/utils/totp';

	export let show = false;
	export let mode:
		| 'decrypt'
		| 'encrypt'
		| 'confirm'
		| 'prompt'
		| 'multiselect'
		| 'totp'
		| 'totpSetup' = 'decrypt';
	export let title = '';
	export let message = '';
	export let error = '';
	export let placeholder = '';
	export let inputType = 'text';
	export let items: { label: string; value: unknown }[] = [];
	export let initialValue: unknown = null;
	export let totpActive: boolean | null = null;
	export let onConfirm: (value: unknown) => void;
	export let onCancel: () => void;
	export let confirmButtonText = '';

	let inputValue: string | unknown[] | boolean = '';
	let totpSecret = '';
	let totpQr = '';
	let totpEnabled = false;
	let totpInitialized = false;
	let totpLoading = false;
	let totpError = '';
	let displayError = '';

	$: displayError = error || totpError;

	$: if (!show) resetModal();

	$: if (show && mode === 'totpSetup' && !totpInitialized) {
		totpInitialized = true;
		if (totpActive !== null) {
			totpEnabled = totpActive;
		}
		initializeTotp();
	}

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
			totpError = data?.message || 'Failed to start TOTP enrollment.';
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

	async function handleSubmit() {
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

	$: displayTitle =
		title ||
		(mode === 'decrypt'
			? 'Enter password to decrypt'
			: mode === 'encrypt'
				? 'Enter password to encrypt'
				: mode === 'confirm'
					? 'Confirm action'
					: mode === 'multiselect'
						? 'Select items'
						: mode === 'totpSetup'
							? 'Set up two-factor authentication'
							: mode === 'totp'
								? 'Enter TOTP code'
								: 'Enter value');

	$: confirmLabel =
		confirmButtonText ||
		(mode === 'decrypt'
			? 'Decrypt'
			: mode === 'encrypt'
				? 'Encrypt'
				: mode === 'confirm'
					? 'Delete'
					: mode === 'totpSetup'
						? totpEnabled
							? 'Disable'
							: 'Enable'
						: 'Confirm');
	$: shouldShowInput = mode !== 'confirm' && mode !== 'multiselect' && mode !== 'totpSetup';
</script>

{#if show}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
		<form
			on:submit|preventDefault={handleSubmit}
			class="w-full max-w-md rounded bg-neutral-900 p-6"
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
										on:click={copySecret}
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
							on:input={onCodeInput}
							class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
						/>
					{/if}
				</div>
			{:else if shouldShowInput}
				<input
					type={inputType}
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
					on:click={onCancel}
					class="cursor-pointer rounded border border-neutral-700 px-4 py-2 text-white hover:bg-neutral-950"
				>
					Cancel
				</button>
			</div>
		</form>
	</div>
{/if}
