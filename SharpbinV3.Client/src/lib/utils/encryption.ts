import { argon2id } from 'hash-wasm';

function toBase64(bytes: Uint8Array): string {
	let binary = '';
	const chunkSize = 0x8000;
	for (let i = 0; i < bytes.length; i += chunkSize) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
	}
	return btoa(binary);
}

function fromBase64(data: string): Uint8Array {
	const binary = atob(data);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

export async function encryptAES(content: string, password: string): Promise<string> {
	const enc = new TextEncoder();
	const salt = window.crypto.getRandomValues(new Uint8Array(32));
	const memorySize = 65536;
	const iterations = 3;
	const parallelism = 1;

	const keyMaterial = await argon2id({
		password,
		salt,
		iterations,
		memorySize,
		parallelism,
		hashLength: 32,
		outputType: 'binary'
	});

	const key = await window.crypto.subtle.importKey(
		'raw',
		keyMaterial as unknown as BufferSource,
		{ name: 'AES-GCM' },
		false,
		['encrypt']
	);

	const iv = window.crypto.getRandomValues(new Uint8Array(12));
	const encryptedContent = await window.crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv
		},
		key,
		enc.encode(content)
	);

	const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength);
	combined.set(salt, 0);
	combined.set(iv, salt.byteLength);
	combined.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

	return JSON.stringify({
		version: 4,
		kdf: 'Argon2id',
		memorySize,
		iterations,
		parallelism,
		algorithm: 'AES-GCM',
		saltLength: salt.byteLength,
		ivLength: iv.byteLength,
		data: toBase64(combined)
	});
}

export function estimateEncryptedSize(content: string): number {
	const rawSize = new TextEncoder().encode(content).length;
	const combinedSize = rawSize + 60;
	const b64Size = Math.ceil(combinedSize / 3) * 4;
	return b64Size + 150;
}

export async function decryptAES(result: string, password: string): Promise<string | null> {
	try {
		const enc = new TextEncoder();
		const parsed = JSON.parse(result);
		const combined = fromBase64(parsed.data);

		const saltLength = parsed.saltLength || 16;
		const ivLength = parsed.ivLength || 12;
		const salt = combined.slice(0, saltLength);
		const iv = combined.slice(saltLength, saltLength + ivLength);
		const data = combined.slice(saltLength + ivLength);

		let keyMaterial: ArrayBuffer | Uint8Array;

		if (parsed.kdf === 'Argon2id') {
			keyMaterial = await argon2id({
				password,
				salt,
				iterations: parsed.iterations,
				memorySize: parsed.memorySize,
				parallelism: parsed.parallelism,
				hashLength: 32,
				outputType: 'binary'
			});
		} else {
			const baseKey = await window.crypto.subtle.importKey(
				'raw',
				enc.encode(password),
				{ name: 'PBKDF2' },
				false,
				['deriveBits', 'deriveKey']
			);
			const derivedKey = await window.crypto.subtle.deriveKey(
				{
					name: 'PBKDF2',
					salt,
					iterations: parsed.iterations,
					hash: parsed.hash
				},
				baseKey,
				{ name: 'AES-GCM', length: 256 },
				true,
				['encrypt', 'decrypt']
			);
			keyMaterial = await window.crypto.subtle.exportKey('raw', derivedKey);
		}

		const key = await window.crypto.subtle.importKey(
			'raw',
			keyMaterial as unknown as BufferSource,
			{ name: 'AES-GCM' },
			false,
			['decrypt']
		);

		const decryptedContent = await window.crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv
			},
			key,
			data
		);

		return new TextDecoder().decode(decryptedContent);
	} catch {
		return null;
	}
}
