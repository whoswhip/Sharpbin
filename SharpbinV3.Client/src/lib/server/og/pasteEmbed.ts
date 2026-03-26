export type PasteEmbedMetadataItem = {
	icon:
		| 'size'
		| 'views'
		| 'created'
		| 'expires'
		| 'syntax'
		| 'visibility-0'
		| 'visibility-1'
		| 'visibility-2';
	value: string;
};

export type PasteEmbedProps = {
	title: string;
	uploader: string;
	metadata: PasteEmbedMetadataItem[];
	previewLines: string[];
	isEncrypted: boolean;
};
