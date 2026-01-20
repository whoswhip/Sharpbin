<script lang="ts">
	import { page } from '$app/state';

	$: status = page.status;
	$: error = page.error;
	$: message = error?.message || 'An unexpected error occurred.';
</script>

<svelte:head>
	<title>{status} - Error - Sharpbin</title>
	<meta name="description" content="An error occurred while processing your request." />
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div
		class="w-[95%] max-w-7xl rounded border-2
        border-neutral-800 bg-neutral-900 p-6 text-center"
	>
		<h1 class="mb-4 text-4xl font-bold">Error {status}</h1>
		<p class="mb-2 text-lg">{message}</p>
	</div>
</main>
