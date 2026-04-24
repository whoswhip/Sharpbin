<script lang="ts">
	import type { PageData } from './$types';
	import { resolve } from '$app/paths';
	import { reportStatusLabels, reportTargetLabels, reportTypeLabels } from '$lib/types/report';
	import { tooltip } from '$lib/utils/misc';
	import { getToken } from '$lib/utils/auth';

	interface Props {
		data: PageData;
	}

	let { data }: Props = $props();
	const initialReport = () => ({ ...data.report });

	let report = $state(initialReport());
	let saving = $state(false);
	let saveError = $state('');
	let statusOptions = $derived(data.options?.statuses ?? []);
	let typeOptions = $derived(data.options?.types ?? []);
	let statusValue = $state(reportStatusLabels[report.status] ?? '');
	let typeValue = $state(reportTypeLabels[report.type] ?? '');

	async function updateReport() {
		saveError = '';
		saving = true;
		const token = getToken();
		const res = await fetch(`/api/report/${report.reportID}`, {
			method: 'PATCH',
			headers: {
				'Content-Type': 'application/json',
				...(token ? { Authorization: `Bearer ${token}` } : {})
			},
			body: JSON.stringify({ status: statusValue, type: typeValue })
		});
		if (!res.ok) {
			const { message } = await res.json().catch(() => ({}));
			saveError = message ?? 'Failed to update report.';
			saving = false;
			return;
		}
		const updated = await res.json();
		report.status = updated.status ?? report.status;
		report.type = updated.type ?? report.type;
		report.updatedAt = updated.updatedAt ?? report.updatedAt;
		report.description = updated.description ?? report.description;
		saving = false;
	}
</script>

<svelte:head>
	<title>Report #{report.reportID} - Sharpbin</title>
</svelte:head>

<main
	class="flex min-h-[calc(100vh-120px)] w-full flex-col items-center justify-center pt-5 pb-5 text-white"
>
	<div class="mx-auto w-[95%] max-w-4xl rounded border-2 border-neutral-800 bg-neutral-900 p-6">
		<h1 class="mb-6 text-center text-3xl font-bold">Report #{report.reportID}</h1>
		<div class="space-y-4">
			<div class="flex flex-wrap items-center gap-3 text-neutral-300">
				<span class="rounded bg-neutral-800 px-3 py-1">
					{reportTypeLabels[report.type] ?? 'Other'}
				</span>
				<span class="rounded bg-neutral-800 px-3 py-1">
					{reportStatusLabels[report.status] ?? 'Open'}
				</span>
				<span class="rounded bg-neutral-800 px-3 py-1">
					{reportTargetLabels[report.targetType] ?? 'Unknown'}
				</span>
			</div>

			<div class="space-y-2 text-sm text-neutral-400">
				<div>
					Reporter:
					{#if report.reporterUsername}
						<a
							class="text-neutral-200 hover:text-white hover:underline"
							href={resolve(`/user/${report.reporterUsername}`)}
							use:tooltip={report.reporterUUID}
						>
							{report.reporterDisplayName || report.reporterUsername}
						</a>
					{:else}
						<span>{report.reporterUUID}</span>
					{/if}
				</div>
				{#if report.pasteId}
					<div>
						Target Paste:
						<a
							class="text-neutral-200 hover:text-white hover:underline"
							href={resolve(`/${report.pasteId}`)}
						>
							{report.pasteTitle !== '' ? report.pasteTitle : report.pasteId}
						</a>
					</div>
				{/if}
				{#if report.userUUID}
					<div>
						Target User:
						{#if report.targetUsername}
							<a
								class="text-neutral-200 hover:text-white hover:underline"
								href={resolve(`/user/${report.targetUsername}`)}
								use:tooltip={report.userUUID}
							>
								{report.targetDisplayName || report.targetUsername}
							</a>
						{:else}
							<span>{report.userUUID}</span>
						{/if}
					</div>
				{/if}
				<div>Created: {new Date(report.createdAt * 1000).toLocaleString()}</div>
				{#if report.updatedAt}
					<div>Updated: {new Date(report.updatedAt * 1000).toLocaleString()}</div>
				{/if}
			</div>

			{#if data.canEdit}
				<div class="mt-4 space-y-3">
					<div class="grid grid-cols-1 gap-3 md:grid-cols-2">
						<div class="flex flex-col gap-2">
							<label class="text-sm text-neutral-400" for="report-update-type">Type</label>
							<select
								id="report-update-type"
								class="rounded border border-neutral-700 bg-neutral-800 p-2"
								bind:value={typeValue}
							>
								{#each typeOptions as t (t)}
									<option value={t}>{t}</option>
								{/each}
							</select>
						</div>
						<div class="flex flex-col gap-2">
							<label class="text-sm text-neutral-400" for="report-update-status">Status</label>
							<select
								id="report-update-status"
								class="rounded border border-neutral-700 bg-neutral-800 p-2"
								bind:value={statusValue}
							>
								{#each statusOptions as s (s)}
									<option value={s}>{s}</option>
								{/each}
							</select>
						</div>
					</div>
					<div class="flex items-center gap-3">
						<button
							class="rounded bg-neutral-700 px-4 py-2 text-sm font-medium transition-colors hover:bg-neutral-600 disabled:opacity-60"
							onclick={updateReport}
							disabled={saving}
						>
							{saving ? 'Saving...' : 'Update Report'}
						</button>
						{#if saveError}
							<span class="text-sm text-red-300">{saveError}</span>
						{/if}
					</div>
				</div>
			{/if}

			{#if report.description}
				<div class="rounded border border-neutral-700 bg-neutral-800 p-4 text-neutral-200">
					{report.description}
				</div>
			{/if}
		</div>
	</div>
</main>
