import { syntaxes } from '$lib/consts';
import { apiUrl } from '$lib/server/api';
import {
	getCachedOgImage,
	getCacheControlHeader,
	getCacheTtlSeconds,
	scheduleOgImageCachePurge,
	storeCachedOgImage
} from '$lib/server/og/cache';
import OgPasteEmbed from '$lib/server/og/PasteEmbed.svelte';
import type { PasteEmbedProps } from '$lib/server/og/pasteEmbed';
import type { Paste } from '$lib/types/paste';
import {
	dateToRelativeString,
	extractDateFromUUIDv7,
	formatBytes,
	formatNumber
} from '$lib/utils/misc';
import { Resvg } from '@resvg/resvg-js';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import satori from 'satori';
import { html } from 'satori-html';
import sharp from 'sharp';
import type { Component } from 'svelte';
import { render } from 'svelte/server';
import type { RequestHandler } from './$types';

const WIDTH = 1200;
const HEIGHT = 630;

const require = createRequire(import.meta.url);

type FontConfig = {
	name: string;
	data: Buffer;
	weight: 400 | 700;
	style: 'normal';
};

type GeneratedImage = {
	jpg: Buffer;
	cacheControl: string;
};
const generationInFlight = new Map<string, Promise<GeneratedImage>>();

const visibilityLabels: Record<Paste['visibility'], string> = {
	0: 'Public',
	1: 'Unlisted',
	2: 'Private'
};

const fontsPromise: Promise<FontConfig[]> = Promise.all([
	readFile(require.resolve('@fontsource/inter/files/inter-latin-400-normal.woff')),
	readFile(require.resolve('@fontsource/inter/files/inter-latin-700-normal.woff')),
	readFile(require.resolve('@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff'))
]).then(([inter400, inter700, mono400]) => [
	{ name: 'Inter', data: inter400, weight: 400, style: 'normal' },
	{ name: 'Inter', data: inter700, weight: 700, style: 'normal' },
	{ name: 'JetBrains Mono', data: mono400, weight: 400, style: 'normal' }
]);

function getPreviewLines(content: string): string[] {
	return content
		.split('\n')
		.slice(0, 15)
		.map((line) => {
			const normalized = line.replace(/\t/g, '    ');
			return normalized.length > 86 ? `${normalized.slice(0, 83)}...` : normalized;
		});
}

const entityMap: Record<string, string> = {
	lt: '<',
	gt: '>',
	amp: '&',
	quot: '"',
	'#39': "'",
	'#x27': "'"
};

// satori sanitizes html but doesnt render them properly (stays as &lt; for example)
// so replace sanitized entities with the actual characters
function decodeHtmlEntities(value: string): string {
	let output = value;
	for (;;) {
		const next = output.replace(
			/&(lt|gt|amp|quot|#39|#x27);/g,
			(_, entity: string) => entityMap[entity]
		);
		if (next === output) return next;
		output = next;
	}
}

function normalizeSatoriTextNodes(node: unknown): unknown {
	if (typeof node === 'string') return decodeHtmlEntities(node);
	if (Array.isArray(node)) return node.map(normalizeSatoriTextNodes);
	if (!node || typeof node !== 'object') return node;

	const props = (node as { props?: { children?: unknown } }).props;
	if (props && 'children' in props) {
		props.children = normalizeSatoriTextNodes(props.children);
	}

	if (props && Array.isArray(props.children) && props.children.length === 0) {
		delete (props as Record<string, unknown>).children;
	}

	return node;
}

export const GET: RequestHandler = async ({ params, fetch }) => {
	const id = params.id;
	if (!id) {
		return new Response('Missing paste id.', { status: 400 });
	}

	scheduleOgImageCachePurge();

	const cachedImage = await getCachedOgImage(id);
	if (cachedImage) {
		return new Response(new Uint8Array(cachedImage.jpg), {
			headers: {
				'Content-Type': 'image/jpeg',
				'Cache-Control': getCacheControlHeader(cachedImage.ttlSeconds)
			}
		});
	}

	const existingGeneration = generationInFlight.get(id);
	if (existingGeneration) {
		const generated = await existingGeneration;
		return new Response(new Uint8Array(generated.jpg), {
			headers: {
				'Content-Type': 'image/jpeg',
				'Cache-Control': generated.cacheControl
			}
		});
	}

	const generation = (async (): Promise<GeneratedImage> => {
		const pasteRes = await fetch(`${apiUrl}/api/paste/${id}`);
		if (!pasteRes.ok) {
			throw new Response('Paste not found.', { status: pasteRes.status === 404 ? 404 : 500 });
		}

		const pasteData = (await pasteRes.json()) as { paste?: Paste };
		const paste = pasteData.paste;
		if (!paste) {
			throw new Response('Invalid paste response.', { status: 500 });
		}

		const isEncrypted = paste.visibility === 2;
		let rawContent = '';
		if (!isEncrypted) {
			const rawRes = await fetch(`${apiUrl}/api/paste/${id}/raw`);
			rawContent = rawRes.ok ? await rawRes.text() : '';
		}

		const content = rawContent || 'No content available.';
		const created = paste.createdAt ? new Date(paste.createdAt) : extractDateFromUUIDv7(paste.uuid);
		const metadata: PasteEmbedProps['metadata'] = [
			{ icon: 'size', value: formatBytes(paste.trueSize) },
			{
				icon: 'views',
				value: `${formatNumber(paste.views)} view${paste.views === 1 ? '' : 's'}`
			},
			{ icon: 'created', value: created ? created.toLocaleDateString() : 'Unknown' },
			...(paste.expiresAt
				? [
						{
							icon: 'expires' as const,
							value: `Expires in ${dateToRelativeString(new Date(paste.expiresAt), false)}`
						}
					]
				: []),
			{ icon: 'syntax', value: syntaxes[paste.syntax]?.name ?? paste.syntax },
			{ icon: `visibility-${paste.visibility}`, value: visibilityLabels[paste.visibility] }
		];
		const props: PasteEmbedProps = {
			title: paste.title?.trim() || 'Untitled Paste',
			uploader: paste.author?.username ?? 'Anonymous Uploader',
			metadata,
			previewLines: isEncrypted ? [] : getPreviewLines(content),
			isEncrypted
		};

		const fonts = await fontsPromise;
		const markup = render(OgPasteEmbed as unknown as Component<PasteEmbedProps>, { props }).body;
		const satoriNode = normalizeSatoriTextNodes(html(markup));
		const svg = await satori(satoriNode, { width: WIDTH, height: HEIGHT, fonts });
		const png = new Resvg(svg, { fitTo: { mode: 'width', value: WIDTH } }).render().asPng();
		const jpg = await sharp(png).jpeg({ quality: 92, mozjpeg: true }).toBuffer();

		const cacheTtlSeconds = getCacheTtlSeconds(paste.expiresAt);
		const cacheControl = getCacheControlHeader(cacheTtlSeconds);
		await storeCachedOgImage({ id, jpg, pasteExpiresAt: paste.expiresAt ?? null }).catch(
			() => undefined
		);

		return { jpg, cacheControl };
	})();

	generationInFlight.set(id, generation);

	try {
		const generated = await generation;
		return new Response(new Uint8Array(generated.jpg), {
			headers: {
				'Content-Type': 'image/jpeg',
				'Cache-Control': generated.cacheControl
			}
		});
	} catch (error) {
		if (error instanceof Response) {
			return error;
		}
		throw error;
	} finally {
		generationInFlight.delete(id);
	}
};
