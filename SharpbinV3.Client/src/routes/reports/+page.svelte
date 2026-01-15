<script lang="ts">
	import type { PageData } from './$types';
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import { reportStatusLabels, reportTargetLabels, reportTypeLabels } from '$lib/types/report';
	import { tooltip } from '$lib/utils/misc';
	import { SvelteURLSearchParams } from 'svelte/reactivity';

	export let data: PageData;

	let target = data.filters.target;
	let status = data.filters.status;
	let type = data.filters.type ?? '';
	let pasteId = data.filters.pasteId;
	let userUuid = data.filters.userUuid;
	let mixedTarget = target === 'all' ? pasteId || userUuid : '';
	let inputTimer: ReturnType<typeof setTimeout> | null = null;

	const targets = [
		{ value: 'all', label: 'All' },
		{ value: 'pastes', label: 'Pastes' },
		{ value: 'users', label: 'Users' }
	];

	const statuses = data.options?.statuses ?? [];
	const types = data.options?.types ?? [];
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

	function applyFilters(page = 1) {
		const params = new SvelteURLSearchParams();
		params.set('target', target);
		if (status) params.set('status', status);
		if (type) params.set('type', type);
		if (target === 'pastes' && pasteId.trim()) params.set('pasteId', pasteId.trim());
		if (target === 'users' && userUuid.trim()) params.set('userUuid', userUuid.trim());
		if (target === 'all' && pasteId.trim()) params.set('pasteId', pasteId.trim());
		if (target === 'all' && userUuid.trim()) params.set('userUuid', userUuid.trim());
		params.set('page', String(page));
		// eslint-disable-next-line svelte/no-navigation-without-resolve
		goto(`?${params.toString()}`);
	}

	function scheduleInputApply() {
		if (inputTimer) clearTimeout(inputTimer);
		inputTimer = setTimeout(() => applyFilters(1), 300);
	}

	function handleTargetChange(value: string) {
		target = value as 'all' | 'pastes' | 'users';
		if (target === 'all') {
			mixedTarget = pasteId || userUuid;
			applyFilters(1);
			return;
		}
		if (target === 'pastes') {
			userUuid = '';
			mixedTarget = '';
			applyFilters(1);
			return;
		}
		pasteId = '';
		mixedTarget = '';
		applyFilters(1);
	}

	function handleTargetInput(value: string) {
		if (target === 'pastes') {
			pasteId = value;
			userUuid = '';
			scheduleInputApply();
			return;
		}
		if (target === 'users') {
			userUuid = value;
			pasteId = '';
			scheduleInputApply();
			return;
		}
		mixedTarget = value;
		const trimmed = value.trim();
		if (uuidRegex.test(trimmed)) {
			userUuid = trimmed;
			pasteId = '';
		} else if (/^\d+$/.test(trimmed)) {
			pasteId = trimmed;
			userUuid = '';
		} else {
			pasteId = '';
			userUuid = '';
		}
		scheduleInputApply();
	}
</script>

<svelte:head>
	<title>Reports - Sharpbin</title>
</svelte:head>

<main
	class="flex min-h-[calc(100vh-60px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="mx-auto w-[95%] max-w-6xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-4xl font-bold">Reports</h1>
		<div class="mb-6 grid grid-cols-1 gap-4 md:grid-cols-5">
			<div class="flex flex-col gap-2">
				<label class="text-sm text-neutral-400" for="report-target">Target</label>
				<select
					id="report-target"
					class="rounded border border-neutral-700 bg-neutral-800 p-2"
					bind:value={target}
					on:change={(e) => {
						if (e.currentTarget instanceof HTMLSelectElement) {
							handleTargetChange(e.currentTarget.value);
						}
					}}
				>
					{#each targets as t (t.value)}
						<option value={t.value}>{t.label}</option>
					{/each}
				</select>
			</div>
			<div class="flex flex-col gap-2">
				<label class="text-sm text-neutral-400" for="report-status">Status</label>
				<select
					id="report-status"
					class="rounded border border-neutral-700 bg-neutral-800 p-2"
					bind:value={status}
					on:change={() => applyFilters(1)}
				>
					<option value="">Any</option>
					{#each statuses as s (s)}
						<option value={s}>{s}</option>
					{/each}
				</select>
			</div>
			<div class="flex flex-col gap-2">
				<label class="text-sm text-neutral-400" for="report-type">Type</label>
				<select
					id="report-type"
					class="rounded border border-neutral-700 bg-neutral-800 p-2"
					bind:value={type}
					on:change={() => applyFilters(1)}
				>
					<option value="">Any</option>
					{#each types as t (t)}
						<option value={t}>{t}</option>
					{/each}
				</select>
			</div>
			<div class="flex flex-col gap-2 md:col-span-2">
				<label class="text-sm text-neutral-400" for="report-target-id">
					{target === 'pastes'
						? 'Paste ID'
						: target === 'users'
							? 'User UUID'
							: 'Paste ID or User UUID'}
				</label>
				<input
					id="report-target-id"
					type="text"
					class="rounded border border-neutral-700 bg-neutral-800 p-2"
					placeholder={target === 'pastes'
						? 'Paste ID'
						: target === 'users'
							? 'User UUID'
							: 'Paste ID or User UUID'}
					value={target === 'pastes' ? pasteId : target === 'users' ? userUuid : mixedTarget}
					on:input={(e) => {
						if (e.currentTarget instanceof HTMLInputElement) {
							handleTargetInput(e.currentTarget.value);
						}
					}}
				/>
			</div>
		</div>

		{#if data.reports.reports.length > 0}
			<div class="space-y-3">
				{#each data.reports.reports as report (report.reportID)}
					<div
						class="flex cursor-pointer flex-col gap-2 rounded border border-neutral-700 bg-neutral-800 px-5 py-4 transition-colors duration-200 hover:bg-neutral-700 focus:ring-2 focus:ring-neutral-600 focus:outline-none"
						role="link"
						tabindex="0"
						on:click={() => goto(resolve(`/report/${report.reportID}`))}
						on:keydown={(e) => {
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
									on:click|stopPropagation
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
										on:click|stopPropagation
									>
										{report.targetDisplayName || report.targetUsername}
									</a>
								{:else}
									<span>{report.userUUID}</span>
								{/if}
							{/if}
							{#if report.reporterUsername}
								<a
									href={resolve(`/user/${report.reporterUsername}`)}
									class="text-neutral-300 hover:text-white"
									use:tooltip={report.reporterUUID}
									on:click|stopPropagation
								>
									{report.reporterDisplayName || report.reporterUsername}
								</a>
							{:else}
								<span>{report.reporterUUID}</span>
							{/if}
							<span>Created {new Date(report.createdAt * 1000).toLocaleString()}</span>
						</div>
						{#if report.description}
							<p class="text-sm text-neutral-300">{report.description}</p>
						{/if}
					</div>
				{/each}
			</div>
		{:else}
			<p class="text-center text-neutral-400">No reports found.</p>
		{/if}

		{#if data.reports.pagination.totalPages > 1}
			<div class="mt-6 flex items-center justify-center gap-4">
				<button
					class="rounded bg-neutral-700 px-3 py-1 disabled:opacity-50"
					on:click={() => applyFilters(data.reports.pagination.page - 1)}
					disabled={data.reports.pagination.page <= 1}
				>
					Prev
				</button>
				<span class="text-neutral-400">
					Page {data.reports.pagination.page} of {data.reports.pagination.totalPages}
				</span>
				<button
					class="rounded bg-neutral-700 px-3 py-1 disabled:opacity-50"
					on:click={() => applyFilters(data.reports.pagination.page + 1)}
					disabled={data.reports.pagination.page >= data.reports.pagination.totalPages}
				>
					Next
				</button>
			</div>
		{/if}
	</div>
</main>
