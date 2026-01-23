import { marked } from 'marked';
import createDOMPurify from 'dompurify';
import type { WindowLike } from 'dompurify';
import { trustedDomains } from '$lib/consts';

const tagMap: Record<string, string> = {
	IMG: 'image',
	VIDEO: 'video',
	AUDIO: 'audio',
	IFRAME: 'iframe'
};

export async function parseMarkdown(md: string, preventExternal: boolean = true, allowTrustedDomains: boolean = true): Promise<string> {
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

				if (element.getAttribute('alt'))
					button.setAttribute('data-alt', element.getAttribute('alt') || '');
				if (element.getAttribute('title'))
					button.setAttribute('data-title', element.getAttribute('title') || '');
				if (element.getAttribute('width'))
					button.setAttribute('data-width', element.getAttribute('width') || '');
				if (element.getAttribute('height'))
					button.setAttribute('data-height', element.getAttribute('height') || '');

				placeholder.appendChild(warning);
				placeholder.appendChild(subWarning);
				placeholder.appendChild(button);

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
