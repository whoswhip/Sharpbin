<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import { cancelModal, confirmModal, modal } from '$lib/stores/modal';

	$: state = $modal;
</script>

<Modal
	show={state.show}
	mode={state.mode}
	title={state.title}
	message={state.message}
	error={state.error}
	placeholder={state.placeholder}
	inputType={state.inputType}
	inputMaxLength={state.maxInputLength ?? null}
	items={state.items}
	initialValue={state.initialValue}
	totpActive={state.totpActive}
	reportTarget={state.reportTarget}
	reportTargetId={state.reportTargetId}
	reportSiteKey={state.reportSiteKey}
	confirmButtonText={state.confirmButtonText}
	onConfirm={(value) => confirmModal(value)}
	onCancel={() => cancelModal()}
/>
