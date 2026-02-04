<script lang="ts">
	import type { PageData } from './$types';
	import { formatBytes, formatNumber, tooltip } from '$lib/utils/misc';
	import { FileText, Users, Database, TrendingUp } from '@lucide/svelte';

	export let data: PageData;
	$: stats = data.stats.stats;

	$: dailyData = stats.pastes.daily || [];
	$: maxCount = Math.max(...dailyData.map((d: any) => d.count), 5);

	function getOrdinal(n: number) {
		const s = ['th', 'st', 'nd', 'rd'];
		const v = n % 100;
		return s[(v - 20) % 10] || s[v] || s[0];
	}

	function formatDate(timestamp: number) {
		const date = new Date(timestamp);
		const day = date.getDate();
		const options: Intl.DateTimeFormatOptions = { month: 'short', day: 'numeric' };
		const locale = typeof navigator !== 'undefined' ? navigator.language : 'en-US';

		if (!locale.startsWith('en')) {
			return date.toLocaleDateString(locale, options);
		}

		const month = date.toLocaleString(locale, { month: 'short' });
		const suffix = getOrdinal(day);

		const parts = new Intl.DateTimeFormat(locale, { month: 'short', day: 'numeric' }).formatToParts(
			date
		);
		if (parts[0].type === 'day') {
			return `${day}${suffix} ${month}`;
		}
		return `${month} ${day}${suffix}`;
	}
</script>

<svelte:head>
	<title>Statistics - Sharpbin</title>
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="w-[95%] max-w-7xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-4xl font-bold">Statistics</h1>
		<div class="mb-8 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
			<div class="flex items-center space-x-4 rounded-lg bg-neutral-800 p-4">
				<div class="rounded-full bg-neutral-500/20 p-3 text-white">
					<FileText size={24} />
				</div>
				<div>
					<p class="text-sm text-neutral-400">Total Pastes</p>
					<p class="text-2xl font-bold">{formatNumber(stats.pastes.total)}</p>
				</div>
			</div>
			<div class="flex items-center space-x-4 rounded-lg bg-neutral-800 p-4">
				<div class="rounded-full bg-neutral-500/20 p-3 text-white">
					<TrendingUp size={24} />
				</div>
				<div>
					<p class="text-sm text-neutral-400">Last 7 Days</p>
					<p class="text-2xl font-bold">{formatNumber(stats.pastes.past7Days)}</p>
				</div>
			</div>
			<div class="flex items-center space-x-4 rounded-lg bg-neutral-800 p-4">
				<div class="rounded-full bg-neutral-500/20 p-3 text-white">
					<Database size={24} />
				</div>
				<div>
					<p class="text-sm text-neutral-400">Total Storage Used</p>
					<p class="text-2xl font-bold">{formatBytes(stats.pastes.totalSizeInBytes)}</p>
				</div>
			</div>
			<div class="flex items-center space-x-4 rounded-lg bg-neutral-800 p-4">
				<div class="rounded-full bg-neutral-500/20 p-3 text-white">
					<Users size={24} />
				</div>
				<div>
					<p class="text-sm text-neutral-400">Total Users</p>
					<p class="text-2xl font-bold">{formatNumber(stats.users.total)}</p>
				</div>
			</div>
		</div>

		<div class="rounded-lg bg-neutral-800 p-6">
			<h2 class="mb-6 text-xl font-semibold">Pastes Growth (Last 7 Days)</h2>
			<div class="flex h-64 w-full items-end justify-between gap-2 px-2">
				{#if dailyData.length > 0}
					{#each dailyData as d}
						<div class="group relative flex h-full flex-1 flex-col justify-end">
							<div
								use:tooltip={[`${formatNumber(d.count)} pastes`, true]}
								class="w-full rounded-t-sm bg-neutral-600 transition-all hover:bg-neutral-500"
								style="height: {d.count === 0 ? '2px' : Math.max((d.count / maxCount) * 95, 2)}%"
							></div>
							<div
								class="absolute top-full mt-2 w-full text-center text-[10px] text-neutral-400 sm:text-xs"
							>
								{formatDate(d.date)}
							</div>
						</div>
					{/each}
				{:else}
					<div class="flex h-full w-full items-center justify-center text-neutral-500">
						No data available for the last 7 days.
					</div>
				{/if}
			</div>
			<div class="h-6"></div>
		</div>
	</div>
</main>
