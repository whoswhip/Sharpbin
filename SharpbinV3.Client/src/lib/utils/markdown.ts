import { marked } from 'marked';
import createDOMPurify from 'dompurify';
import type { WindowLike } from 'dompurify';
import { trustedDomains } from '$lib/consts';
import { escapeHtml } from './html';

export const externalMediaWarningStorageKey = 'sharpbin:ignore-external-media-warning';

const tagMap: Record<string, string> = {
	IMG: 'image',
	VIDEO: 'video',
	AUDIO: 'audio',
	IFRAME: 'iframe'
};

export function getIgnoreExternalMediaWarning(): boolean {
	if (typeof window === 'undefined') return false;

	return window.localStorage.getItem(externalMediaWarningStorageKey) === 'true';
}

export function setIgnoreExternalMediaWarning(ignore: boolean) {
	if (typeof window === 'undefined') return;

	window.localStorage.setItem(externalMediaWarningStorageKey, ignore ? 'true' : 'false');
}

export async function parseMarkdown(
	md: string,
	preventExternal: boolean = true,
	allowTrustedDomains: boolean = true
): Promise<string> {
	const html = await marked.parse(md);
	let dom: WindowLike & { document: Document };

	if (typeof window !== 'undefined') {
		dom = window as unknown as WindowLike & { document: Document };
	} else if (import.meta.env.SSR) {
		const { JSDOM } = await import('jsdom');
		dom = new JSDOM('').window as unknown as WindowLike & { document: Document };
	} else {
		throw new Error('JSDOM should only be loaded on the server');
	}

	const DOMPurify = createDOMPurify(dom);

	if (preventExternal) {
		DOMPurify.addHook('afterSanitizeElements', (node) => {
			if (node.nodeType !== 1) return;
			const element = node as Element;

			const tag = element.nodeName;
			if (tag === 'IMG' || tag === 'VIDEO' || tag === 'IFRAME' || tag === 'AUDIO') {
				const src = element.getAttribute('src');
				if (!src) return;

				let hostname = 'external server';

				try {
					hostname = new URL(src).hostname;
				} catch {
					//might be a relative url
				}

				if (allowTrustedDomains && trustedDomains.includes(hostname)) return;

				const placeholder = dom.document.createElement('span');
				placeholder.className = 'media-placeholder';
				placeholder.setAttribute(
					'style',
					'border: 1px solid #404040; padding: 1rem; margin: 1rem 0; border-radius: 0.5rem; background-color: #1e1e1e; text-align: center; display: block; font-style: normal; color: white; cursor: default; text-decoration: none; user-select: none;'
				);

				const warning = dom.document.createElement('span');
				warning.textContent = `External ${tagMap[tag] || tag.toLowerCase()} hidden for privacy.`;
				warning.setAttribute(
					'style',
					'margin-bottom: 0.5rem; font-weight: bold; display: block; text-decoration: none;'
				);

				const subWarning = dom.document.createElement('span');
				subWarning.textContent = `Loading this will expose your IP address to ${hostname}.`;
				subWarning.setAttribute(
					'style',
					'font-size: 0.75rem; color: #a3a3a3; margin-bottom: 1rem; display: block; text-decoration: none;'
				);

				const button = dom.document.createElement('button');
				button.textContent = `Load ${tagMap[tag] || tag.toLowerCase()}`;
				button.className = 'load-media-btn';
				button.setAttribute('data-src', src);
				button.setAttribute('data-tag', tag.toLowerCase());
				button.setAttribute(
					'style',
					'background-color: #404040; color: white; padding: 0.25rem 0.75rem; border-radius: 0.25rem; cursor: pointer; text-decoration: none;'
				);

				const ignoreButton = dom.document.createElement('button');
				ignoreButton.textContent = "Don't warn again";
				ignoreButton.className = 'ignore-media-warning-btn';
				ignoreButton.setAttribute(
					'style',
					'background-color: transparent; color: #d4d4d8; padding: 0.25rem 0.75rem; border: 1px solid #525252; border-radius: 0.25rem; cursor: pointer; text-decoration: none;'
				);

				if (element.getAttribute('alt'))
					button.setAttribute('data-alt', element.getAttribute('alt') || '');
				if (element.getAttribute('title'))
					button.setAttribute('data-title', element.getAttribute('title') || '');
				if (element.getAttribute('width'))
					button.setAttribute('data-width', element.getAttribute('width') || '');
				if (element.getAttribute('height'))
					button.setAttribute('data-height', element.getAttribute('height') || '');

				const actions = dom.document.createElement('span');
				actions.setAttribute(
					'style',
					'display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap;'
				);
				actions.appendChild(button);
				actions.appendChild(ignoreButton);

				placeholder.appendChild(warning);
				placeholder.appendChild(subWarning);
				placeholder.appendChild(actions);

				const parent = element.parentNode;
				if (parent && parent.nodeName === 'A') {
					const anchor = parent as HTMLElement;
					button.setAttribute('data-href', anchor.getAttribute('href') || '');
					button.setAttribute('data-target', anchor.getAttribute('target') || '');
					anchor.parentNode?.replaceChild(placeholder, anchor);
				} else {
					element.parentNode?.replaceChild(placeholder, element);
				}
			}
		});
	}

	return DOMPurify.sanitize(html);
}

export function parseCommentMarkdown(text: string): string {
	const lines = text.replace(/\r\n?/g, '\n').split('\n');
	const output: string[] = [];
	let index = 0;

	while (index < lines.length) {
		const codeBlock = tryParseCodeBlock(lines, index);
		if (codeBlock) {
			output.push(codeBlock.html);
			index = codeBlock.nextIndex;
			continue;
		}

		const spoilerBlock = tryParseSpoilerBlock(lines, index);
		if (spoilerBlock) {
			output.push(spoilerBlock.html);
			index = spoilerBlock.nextIndex;
			continue;
		}

		const quoteBlock = tryParseQuoteBlock(lines, index);
		if (quoteBlock) {
			output.push(quoteBlock.html);
			index = quoteBlock.nextIndex;
			continue;
		}

		if (/^\s*---\s*$/.test(lines[index])) {
			output.push('<hr class="my-2 border-t border-neutral-700" />');
			index += 1;
			continue;
		}

		output.push(parseInlineElements(lines[index]));
		index += 1;
	}

	return output.join('');
}

interface ParsedCommentBlock {
	html: string;
	nextIndex: number;
}

function tryParseCodeBlock(lines: string[], startIndex: number): ParsedCommentBlock | null {
	const firstLine = lines[startIndex];
	if (!firstLine.startsWith('```')) return null;

	const inlineCloseIndex = firstLine.indexOf('```', 3);
	if (inlineCloseIndex > -1) {
		const code = firstLine.slice(3, inlineCloseIndex);
		const trailing = firstLine.slice(inlineCloseIndex + 3).trim();
		const html = renderCodeBlock(code);
		if (trailing.length === 0) {
			return { html, nextIndex: startIndex + 1 };
		}
		return {
			html: `${html}\n${parseInlineElements(trailing)}`,
			nextIndex: startIndex + 1
		};
	}

	const codeLines: string[] = [];
	let index = startIndex + 1;

	while (index < lines.length && !lines[index].startsWith('```')) {
		codeLines.push(lines[index]);
		index += 1;
	}

	if (index < lines.length) index += 1;

	return {
		html: renderCodeBlock(codeLines.join('\n')),
		nextIndex: index
	};
}

function tryParseSpoilerBlock(lines: string[], startIndex: number): ParsedCommentBlock | null {
	const spoilerOpenMatch = lines[startIndex].match(/^\[Spoiler(?:="([^"]*)")?\](.*)$/i);
	if (!spoilerOpenMatch) return null;

	const title = spoilerOpenMatch[1]?.trim() || 'Spoiler';
	const contentParts: string[] = [];
	let remainder = spoilerOpenMatch[2] ?? '';
	let index = startIndex;

	while (true) {
		const closeMatch = /\[\/spoiler\]/i.exec(remainder);
		if (closeMatch && closeMatch.index !== undefined) {
			const beforeClose = remainder.slice(0, closeMatch.index);
			if (beforeClose.length > 0) contentParts.push(beforeClose);

			const contentHtml = contentParts.map((line) => parseInlineElements(line)).join('<br />');
			let html = `<details class="rounded-sm my-2 bg-neutral-800"><summary class="cursor-pointer px-2 py-1 font-semibold text-neutral-300 hover:text-neutral-200 w-full">${escapeHtml(title)}</summary><div class=" text-neutral-300 bg-neutral-700/40 px-2 p-2 rounded-b-sm">${contentHtml}</div></details>`;

			const afterClose = remainder.slice(closeMatch.index + closeMatch[0].length).trim();
			if (afterClose.length > 0) {
				html += `\n${parseInlineElements(afterClose)}`;
			}

			return {
				html,
				nextIndex: index + 1
			};
		}

		if (remainder.length > 0) contentParts.push(remainder);
		index += 1;
		if (index >= lines.length) return null;
		remainder = lines[index];
	}
}

function tryParseQuoteBlock(lines: string[], startIndex: number): ParsedCommentBlock | null {
	if (!lines[startIndex].startsWith('>')) return null;

	const quoteLines: string[] = [];
	let index = startIndex;

	while (index < lines.length && lines[index].startsWith('>')) {
		quoteLines.push(parseInlineElements(lines[index].replace(/^>\s?/, '')));
		index += 1;
	}

	return {
		html: `<blockquote class="border-l-4 border-neutral-600 pl-3 my-2 text-neutral-400 italic">${quoteLines.join('<br />')}</blockquote>`,
		nextIndex: index
	};
}

function renderCodeBlock(code: string): string {
	return `<pre class="my-2 overflow-x-auto rounded bg-neutral-900 p-2"><code class="font-mono text-sm text-neutral-100">${escapeHtml(code)}</code></pre>`;
}

function normalizeCommentLink(rawUrl: string): string | null {
	const url = rawUrl.trim();
	if (url.length === 0) return null;
	if (url.startsWith('/')) return url;

	try {
		const parsed = new URL(url);
		if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
			return parsed.toString();
		}
		return null;
	} catch {
		return null;
	}
}

function parseInlineElements(text: string): string {
	const inlinePattern =
		/```([\s\S]*?)```|\*\*\*([^*\n]+)\*\*\*|\*\*([^*\n]+)\*\*|\*([^*\n]+)\*|`([^`\n]+)`|\[([^\]\n]+)\]\(([^)\n]+)\)|@([a-zA-Z0-9_-]+)/g;

	let output = '';
	let lastIndex = 0;

	for (const match of text.matchAll(inlinePattern)) {
		const index = match.index ?? 0;
		output += escapeHtml(text.slice(lastIndex, index));

		if (match[1] !== undefined) {
			output += renderCodeBlock(match[1]);
		} else if (match[2] !== undefined) {
			output += `<strong class="font-bold"><em class="italic">${escapeHtml(match[2])}</em></strong>`;
		} else if (match[3] !== undefined) {
			output += `<strong class="font-bold">${escapeHtml(match[3])}</strong>`;
		} else if (match[4] !== undefined) {
			output += `<em class="italic">${escapeHtml(match[4])}</em>`;
		} else if (match[5] !== undefined) {
			output += `<code class="bg-neutral-800 px-1 py-0.5 rounded text-neutral-100 font-mono text-sm">${escapeHtml(match[5])}</code>`;
		} else if (match[6] !== undefined && match[7] !== undefined) {
			const safeUrl = normalizeCommentLink(match[7]);
			if (safeUrl) {
				output += `<a href="${escapeHtml(safeUrl)}" class="text-blue-400 hover:underline" target="_blank" rel="noopener noreferrer">${escapeHtml(match[6])}</a>`;
			} else {
				output += escapeHtml(match[0]);
			}
		} else if (match[8] !== undefined) {
			const username = match[8];
			output += `<a href="/user/${encodeURIComponent(username)}" class="text-blue-400 hover:underline">@${escapeHtml(username)}</a>`;
		}

		lastIndex = index + match[0].length;
	}

	output += escapeHtml(text.slice(lastIndex));
	return output;
}
