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
	export let variant: string = '';

	let isOpen = false;
	let searchQuery = '';
	let dropdownElement: HTMLDivElement;
	let dropdownListElement: HTMLDivElement;
	let dropdownMaxHeight = '12rem';

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
		if (isOpen) {
			setTimeout(() => {
				if (dropdownElement && dropdownListElement) {
					const rect = dropdownElement.getBoundingClientRect();
					const spaceBelow = window.innerHeight - rect.bottom - 8;
					const maxCap = 416;
					dropdownMaxHeight = Math.max(120, Math.min(spaceBelow, maxCap)) + 'px';
				}
				if (searchable) {
					const input = dropdownElement?.querySelector('input[type="text"]') as HTMLInputElement;
					input?.focus();
				}
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

<div bind:this={dropdownElement} class="relative mb-2 w-full" class:dropdown-sm={variant === 'sm'}>
	<button
		type="button"
		on:click={toggleDropdown}
		class="w-full rounded border border-neutral-700 bg-neutral-800 p-2 text-left transition-colors hover:bg-neutral-700"
		class:dropdown-sm-btn={variant === 'sm'}
	>
		{displayValue(value) || placeholder}
	</button>

	{#if isOpen}
		<div
			class="absolute top-full z-50 mt-1 w-full rounded border border-neutral-700 bg-neutral-800 shadow-lg"
			class:dropdown-sm-list={variant === 'sm'}
			bind:this={dropdownListElement}
			style="max-height: {dropdownMaxHeight}; width: 100%;"
		>
			{#if searchable}
				<div style="position: sticky; top: 0; z-index: 1; background: inherit;">
					<input
						type="text"
						placeholder="Search..."
						class="w-full border-b border-neutral-700 bg-neutral-800 p-2 outline-none"
						class:dropdown-sm-input={variant === 'sm'}
						bind:value={searchQuery}
						on:keydown={handleKeyDown}
					/>
				</div>
			{/if}
			<div style="overflow-y: auto; max-height: calc({dropdownMaxHeight} - 3rem);">
				{#each filteredOptions as option (option.value)}
					<button
						type="button"
						on:click={() => handleSelect(option.value)}
						class="w-full border-b border-neutral-700 px-3 py-2 text-left last:border-b-0 hover:bg-neutral-600"
						class:bg-neutral-700={value === option.value}
						class:dropdown-sm-option={variant === 'sm'}
					>
						{option.label}
					</button>
				{/each}
			</div>
		</div>
	{/if}
</div>

<style>
	.dropdown-sm {
		margin-bottom: 0;
	}
	.dropdown-sm-btn {
		padding-top: 0;
		padding-bottom: 0;
		padding-left: 0.5rem;
		padding-right: 0.5rem;
		font-size: 0.95rem;
	}
	.dropdown-sm-list {
		min-width: 160px;
	}
	.dropdown-sm-input {
		padding-top: 0;
		padding-bottom: 0;
		padding-left: 0.5rem;
		padding-right: 0.5rem;
		font-size: 0.95rem;
	}
	.dropdown-sm-option {
		padding-top: 0.15rem;
		padding-bottom: 0.15rem;
		padding-left: 0.5rem;
		padding-right: 0.5rem;
		font-size: 0.95rem;
	}
</style>
