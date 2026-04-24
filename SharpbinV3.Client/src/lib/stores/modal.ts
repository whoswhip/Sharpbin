import { writable } from 'svelte/store';
import type { ModalOpenOptions, ModalState } from '$lib/types/modal';

const initialState: ModalState = {
	show: false,
	mode: 'confirm',
	title: '',
	message: '',
	error: '',
	placeholder: '',
	inputType: 'text',
	maxInputLength: undefined,
	items: [],
	initialValue: null,
	totpActive: null,
	reportTarget: null,
	reportTargetId: null,
	reportSiteKey: null,
	confirmButtonText: ''
};

let resolver: ((value: unknown) => void) | null = null;
let cancelValue: unknown = '';

export const modal = writable<ModalState>(initialState);

export function openModal<T = unknown>(options: ModalOpenOptions): Promise<T> {
	cancelValue = options.cancelValue ?? '';
	return new Promise<T>((resolve) => {
		resolver = resolve as (value: unknown) => void;
		modal.set({
			...initialState,
			...options,
			show: true
		});
	});
}

export function confirmModal(value: unknown) {
	const resolve = resolver;
	resolver = null;
	modal.set(initialState);
	resolve?.(value);
}

export function cancelModal() {
	const resolve = resolver;
	resolver = null;
	modal.set(initialState);
	resolve?.(cancelValue);
}
