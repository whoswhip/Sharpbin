<script lang="ts">
	import CalendarDays from '@lucide/svelte/icons/calendar-days';
	import CalendarOff from '@lucide/svelte/icons/calendar-off';
	import Code from '@lucide/svelte/icons/code';
	import Eye from '@lucide/svelte/icons/eye';
	import EyeOff from '@lucide/svelte/icons/eye-off';
	import FileBox from '@lucide/svelte/icons/file-box';
	import Globe from '@lucide/svelte/icons/globe';
	import Lock from '@lucide/svelte/icons/lock';
	import User from '@lucide/svelte/icons/user';
	import type { PasteEmbedProps } from './pasteEmbed';

	interface Props {
		title: PasteEmbedProps['title'];
		uploader: PasteEmbedProps['uploader'];
		metadata: PasteEmbedProps['metadata'];
		previewLines: PasteEmbedProps['previewLines'];
		isEncrypted: PasteEmbedProps['isEncrypted'];
	}

	let { title, uploader, metadata, previewLines, isEncrypted }: Props = $props();

	const metadataIcons = {
		size: FileBox,
		views: Eye,
		created: CalendarDays,
		expires: CalendarOff,
		syntax: Code,
		'visibility-0': Globe,
		'visibility-1': EyeOff,
		'visibility-2': Lock
	} as const;
</script>

<!-- 
	the following tailwindcss styles fail to parse, so they are applied inline: 
		neutral-950
		gap-1.5
		truncate
		whitespace-nowrap
		gap-2
		gap-x-6.5
		gap-y-3
		gap-0.75
		gap-3
		whitespace-pre
-->
<!-- 630px by 1200px -->
<div class="flex h-157.5 w-300 p-6" style="font-family:'Inter'; background-color: #0a0a0a;">
	<div
		class="flex h-full w-full flex-col rounded-lg border-2 border-neutral-800 bg-neutral-900 p-4"
	>
		<div class="mb-3.5 flex flex-col items-center justify-center" style="gap: 6px;">
			<div
				class="max-w-250 text-[54px] leading-[1.1] font-bold text-white"
				style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"
			>
				{title}
			</div>
			<div class="flex items-center text-[20px] text-neutral-400" style="gap: 8px;">
				<User class="h-4.5 w-4.5 text-neutral-400" />
				<div>{uploader}</div>
			</div>
		</div>
		<div class="mb-3 flex flex-wrap items-center justify-center" style="gap: 12px;">
			{#each metadata as item (item.value)}
				{@const Icon = metadataIcons[item.icon]}
				<div class="flex items-center text-[24px] leading-none text-neutral-400">
					<Icon class="mr-2 h-5.5 w-5.5 text-neutral-400" />
					<div class="text-[24px] text-neutral-400">{item.value}</div>
				</div>
			{/each}
		</div>
		{#if isEncrypted}
			<div
				class="flex flex-1 items-center justify-center overflow-hidden rounded-lg bg-neutral-800"
			>
				<div class="flex flex-col items-center justify-center gap-3.5 p-6">
					<Lock class="h-16 w-16 text-neutral-400" />
					<div class="text-[36px] leading-[1.1] font-bold text-neutral-100">Encrypted Paste</div>
					<div class="max-w-195 text-center text-[20px] leading-[1.3] text-neutral-400">
						Preview is hidden for private encrypted pastes. Open the paste page and decrypt with the
						password to view content.
					</div>
				</div>
			</div>
		{:else}
			<div class="relative flex flex-1 overflow-hidden rounded-lg bg-neutral-800">
				<div class="flex w-full flex-col pt-3" style="gap: 3px;">
					{#each previewLines as line, index (index)}
						<!-- emulates whitespace for indentation since satori doesnt seem to render it properly -->
						{@const leadingSpaceCount = line.length - line.trimStart().length}
						{@const contentWithoutIndent = line.trimStart()}
						<div class="flex items-center px-3.5" style="gap: 12px;">
							<div
								class="w-7.5 text-right text-[20px] text-neutral-500"
								style="font-family:'JetBrains Mono'; white-space: pre;"
							>
								{String(index + 1).padStart(3, ' ')}
							</div>
							<div
								class="flex items-center text-[20px] text-neutral-100"
								style="font-family:'JetBrains Mono'; white-space: pre;"
							>
								<div style={`width: ${leadingSpaceCount * 12}px;`}></div>
								<div>{contentWithoutIndent}</div>
							</div>
						</div>
					{/each}
				</div>
				<div
					class="absolute right-0 bottom-0 left-0"
					style="height: 58px; background: linear-gradient(to bottom, rgba(38, 38, 38, 0), rgba(38, 38, 38, 1));"
				></div>
			</div>
		{/if}
	</div>
</div>
