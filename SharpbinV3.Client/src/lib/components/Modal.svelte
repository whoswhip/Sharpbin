<script lang="ts">
	export let show = false;
	export let mode: 'decrypt' | 'encrypt' | 'confirm' | 'prompt' = 'decrypt';
	export let title = '';
	export let message = '';
	export let error = '';
	export let placeholder = '';
	export let inputType = 'text';
	export let onConfirm: (value: string | boolean) => void;
	export let onCancel: () => void;
	export let confirmButtonText = '';

	let inputValue = '';

	$: if (!show) {
		inputValue = '';
	}

	function handleSubmit() {
		if (mode === 'confirm') {
			onConfirm(true);
		} else {
			onConfirm(inputValue);
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
					: 'Enter value');

	$: confirmLabel = 
		confirmButtonText || 
		(mode === 'decrypt' ? 'Decrypt' : 
		mode === 'encrypt' ? 'Encrypt' : 
		mode === 'confirm' ? 'Delete' :
		'Confirm');
	$: shouldShowInput = mode !== 'confirm';
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

			{#if shouldShowInput}
				<input
					type={inputType}
					bind:value={inputValue}
					class="mb-3 w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-white outline-none"
					{placeholder}
				/>
			{/if}

			{#if error}
				<div class="mb-3 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
					{error}
				</div>
			{/if}

			<div class="flex gap-2">
				<button
					type="submit"
					class={`flex-1 cursor-pointer rounded px-4 py-2 font-semibold text-white transition-colors ${
						mode === 'confirm' ? 'bg-red-900 hover:bg-red-800' : 'bg-neutral-700 hover:bg-neutral-800'
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
