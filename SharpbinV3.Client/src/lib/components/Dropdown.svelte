<script lang="ts">
	interface Option {
		value: string | number;
		label: string;
	}

	export let options: Option[] = [];
	export let value: string | number = '';
	export let placeholder = 'Select...';
	export let searchable = false;
	export let displayValue: (val: string | number) => string = (val) => {
		return options.find((o) => o.value === val)?.label ?? String(val);
	};

	let isOpen = false;
	let searchQuery = '';
	let dropdownElement: HTMLDivElement;

	$: filteredOptions = searchable
		? options.filter(
				(opt) =>
					opt.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
					String(opt.value).toLowerCase().includes(searchQuery.toLowerCase())
			)
		: options;

	function handleSelect(selectedValue: string | number) {
		value = selectedValue;
		isOpen = false;
		searchQuery = '';
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			isOpen = false;
		}
	}

	function toggleDropdown() {
		isOpen = !isOpen;
		if (isOpen && searchable) {
			setTimeout(() => {
				const input = dropdownElement?.querySelector('input[type="text"]') as HTMLInputElement;
				input?.focus();
			}, 0);
		}
	}

	function handleClickOutside(event: MouseEvent) {
		if (dropdownElement && !dropdownElement.contains(event.target as Node)) {
			isOpen = false;
		}
	}
</script>

<svelte:window on:click={handleClickOutside} />

<div bind:this={dropdownElement} class="relative w-full mb-2">
	<button
		type="button"
		on:click={toggleDropdown}
		class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-left transition-colors hover:bg-neutral-700"
	>
		{displayValue(value) || placeholder}
	</button>

	{#if isOpen}
		<div
			class="absolute top-full z-50 mt-1 w-full rounded border border-neutral-700 bg-neutral-800 shadow-lg"
		>
			{#if searchable}
				<input
					type="text"
					placeholder="Search..."
					class="w-full border-b border-neutral-700 bg-neutral-800 p-2 outline-none"
					bind:value={searchQuery}
					on:keydown={handleKeyDown}
				/>
			{/if}

			<div class="max-h-48 overflow-y-auto">
				{#each filteredOptions as option (option.value)}
					<button
						type="button"
						on:click={() => handleSelect(option.value)}
						class="w-full border-b border-neutral-700 px-3 py-2 text-left last:border-b-0 hover:bg-neutral-600"
						class:bg-neutral-700={value === option.value}
					>
						{option.label}
					</button>
				{/each}
			</div>
		</div>
	{/if}
</div>
