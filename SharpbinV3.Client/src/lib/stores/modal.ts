import { writable } from 'svelte/store';

type ModalMode =
	| 'decrypt'
	| 'encrypt'
	| 'confirm'
	| 'prompt'
	| 'multiselect'
	| 'totp'
	| 'totpSetup'
	| 'report';

type ModalItem = { label: string; value: unknown };

type ModalState = {
	show: boolean;
	mode: ModalMode;
	title: string;
	message: string;
	error: string;
	placeholder: string;
	inputType: string;
	items: ModalItem[];
	initialValue: unknown;
	totpActive: boolean | null;
	reportTarget: 'user' | 'paste' | null;
	reportTargetId: string | number | null;
	reportSiteKey: string | null;
	confirmButtonText: string;
};

type ModalOpenOptions = Partial<Omit<ModalState, 'show'>> & {
	mode: ModalMode;
	cancelValue?: unknown;
};

const initialState: ModalState = {
	show: false,
	mode: 'confirm',
	title: '',
	message: '',
	error: '',
	placeholder: '',
	inputType: 'text',
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
