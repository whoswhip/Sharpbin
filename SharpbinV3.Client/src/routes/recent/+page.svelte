<script lang="ts">
	import type { PageData } from './$types';
	import { onMount } from 'svelte';
	import Paste from '$lib/components/Paste.svelte';

	interface Props {
		data: PageData;
	}

	let { data }: Props = $props();

	let now = $state(new Date());

	onMount(() => {
		const interval = setInterval(() => {
			now = new Date();
		}, 1000);

		return () => clearInterval(interval);
	});
</script>

<svelte:head>
	<title>Recent Pastes - Sharpbin</title>
	<meta name="description" content="Browse the most recent pastes shared on Sharpbin." />
	<meta name="robots" content="noindex, follow" />
	<link rel="canonical" href={data.url} />
	<meta property="og:title" content="Recent Pastes - Sharpbin" />
	<meta property="og:description" content="Browse the most recent pastes shared on Sharpbin." />
	<meta property="og:type" content="website" />
	<meta property="og:url" content={data.url} />
	<meta property="og:site_name" content="Sharpbin" />
	<meta name="twitter:card" content="summary" />
	<meta name="twitter:title" content="Recent Pastes - Sharpbin" />
	<meta name="twitter:description" content="Browse the most recent pastes shared on Sharpbin." />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		{#if data.recentPastes.length === 0}
			<p class="text-lg">No recent pastes available.</p>
		{:else}
			<h1 class="mb-4 text-3xl font-bold">Recent Pastes</h1>
			<div class="grid grid-cols-1 gap-4">
				{#each data.recentPastes as paste (paste.uuid)}
					<Paste {paste} {now} />
				{/each}
			</div>
		{/if}
	</div>
</main>
