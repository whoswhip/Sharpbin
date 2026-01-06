<script lang="ts">
	export let show = false;
	export let mode: 'decrypt' | 'encrypt' | 'confirm' | 'prompt' | 'multiselect' = 'decrypt';
	export let title = '';
	export let message = '';
	export let error = '';
	export let placeholder = '';
	export let inputType = 'text';
	export let items: { label: string; value: unknown }[] = [];
	export let initialValue: unknown = null;
	export let onConfirm: (value: unknown) => void;
	export let onCancel: () => void;
	export let confirmButtonText = '';

	let inputValue: string | unknown[] | boolean = '';

	$: if (!show) {
		inputValue =
			initialValue !== null
				? JSON.parse(JSON.stringify(initialValue))
				: mode === 'multiselect'
					? []
					: '';
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
					: mode === 'multiselect'
						? 'Select items'
						: 'Enter value');

	$: confirmLabel =
		confirmButtonText ||
		(mode === 'decrypt'
			? 'Decrypt'
			: mode === 'encrypt'
				? 'Encrypt'
				: mode === 'confirm'
					? 'Delete'
					: 'Confirm');
	$: shouldShowInput = mode !== 'confirm' && mode !== 'multiselect';
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

			{#if error}
				<div class="mb-3 rounded border border-red-900 bg-red-950 p-2 text-sm text-red-200">
					{error}
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
