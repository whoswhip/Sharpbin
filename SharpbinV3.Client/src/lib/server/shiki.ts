import { createHighlighter } from 'shiki';

import type { Highlighter } from 'shiki';
let highlighterPromise: Promise<Highlighter> | null = null;

async function loadHighlighter() {
	const res = await fetch('http://localhost:5050/api/paste/create/options');
	if (!res.ok) throw new Error('Failed to fetch paste options');

	const data = await res.json();

	return createHighlighter({
		themes: ['github-dark', 'github-light'],
		langs: data.syntaxes
	});
}

export function getShiki() {
	if (!highlighterPromise) {
		highlighterPromise = loadHighlighter();
	}
	return highlighterPromise;
}
