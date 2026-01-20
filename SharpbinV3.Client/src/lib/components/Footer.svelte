<script lang="ts">
	const [major] = __APP_VERSION__.split('.').map(Number);
	const isBeta = major < 1;
</script>

<div
	class="mb-5 max-h-10 w-full border-t border-neutral-800 pt-5 text-center text-sm text-neutral-500"
>
	<a
		href="https://github.com/whoswhip/Sharpbin"
		target="_blank"
		rel="noopener noreferrer"
		class="text-neutral-400 underline hover:text-neutral-200"
	>
		Source Code
	</a>
	<span class="mx-1">•</span>
	v{__APP_VERSION__}{isBeta ? ' (Beta)' : ''}
</div>
