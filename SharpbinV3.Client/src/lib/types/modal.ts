export type ModalMode =
	| 'decrypt'
	| 'encrypt'
	| 'confirm'
	| 'prompt'
	| 'multiselect'
	| 'totp'
	| 'totpSetup'
	| 'report';

export type ModalItem = { label: string; value: unknown };

export type ModalState = {
	show: boolean;
	mode: ModalMode;
	title: string;
	message: string;
	error: string;
	placeholder: string;
	inputType: string;
	maxInputLength?: number;
	items: ModalItem[];
	initialValue: unknown;
	totpActive: boolean | null;
	reportTarget: 'user' | 'paste' | null;
	reportTargetId: string | number | null;
	reportSiteKey: string | null;
	confirmButtonText: string;
};

export type ModalOpenOptions = Partial<Omit<ModalState, 'show'>> & {
	mode: ModalMode;
	cancelValue?: unknown;
};
