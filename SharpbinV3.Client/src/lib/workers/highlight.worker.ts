import hljs from 'highlight.js';

type HighlightRequest = {
	id: number;
	code: string;
	lang: string;
};

type HighlightResponse = {
	id: number;
	html: string;
};

const escapeHtml = (value: string) =>
	value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

self.onmessage = (event: MessageEvent<HighlightRequest>) => {
	const { id, code, lang } = event.data;
	let html = '';
	try {
		if (lang === 'plaintext') {
			html = escapeHtml(code);
		} else if (lang && hljs.getLanguage && hljs.getLanguage(lang)) {
			html = hljs.highlight(code, { language: lang, ignoreIllegals: true }).value;
		} else {
			html = hljs.highlightAuto(code).value;
		}
	} catch {
		if (lang === 'plaintext') {
			html = escapeHtml(code);
		} else {
			html = hljs.highlightAuto(code).value;
		}
	}
	const response: HighlightResponse = { id, html };
	self.postMessage(response);
};
