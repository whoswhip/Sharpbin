import { argon2id } from 'hash-wasm';

const BASE64_CHUNK_SIZE = 0x8000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const ARGON2_MEMORY_SIZE = 262144;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;
const AES_KEY_LENGTH = 256;
const ENCRYPTION_AAD = 'enc-v4';
const ENCRYPTED_DATA_OVERHEAD = 60;
const ENCRYPTED_METADATA_OVERHEAD = 150;

function toBase64(bytes: Uint8Array): string {
	let binary = '';
	for (let i = 0; i < bytes.length; i += BASE64_CHUNK_SIZE) {
		binary += String.fromCharCode(...bytes.subarray(i, i + BASE64_CHUNK_SIZE));
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
	const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

	const keyMaterial = await argon2id({
		password,
		salt,
		iterations: ARGON2_ITERATIONS,
		memorySize: ARGON2_MEMORY_SIZE,
		parallelism: ARGON2_PARALLELISM,
		hashLength: ARGON2_HASH_LENGTH,
		outputType: 'binary'
	});

	const key = await window.crypto.subtle.importKey(
		'raw',
		new Uint8Array(keyMaterial),
		{ name: 'AES-GCM', length: AES_KEY_LENGTH },
		false,
		['encrypt']
	);

	const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const encryptedContent = await window.crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv,
			additionalData: enc.encode(ENCRYPTION_AAD)
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
		memorySize: ARGON2_MEMORY_SIZE,
		iterations: ARGON2_ITERATIONS,
		parallelism: ARGON2_PARALLELISM,
		algorithm: 'AES-GCM',
		saltLength: salt.byteLength,
		ivLength: iv.byteLength,
		data: toBase64(combined)
	});
}

export function estimateEncryptedSize(content: string): number {
	const rawSize = new TextEncoder().encode(content).length;
	const combinedSize = rawSize + ENCRYPTED_DATA_OVERHEAD;
	const b64Size = Math.ceil(combinedSize / 3) * 4;
	return b64Size + ENCRYPTED_METADATA_OVERHEAD;
}

export async function decryptAES(result: string, password: string): Promise<string | null> {
	try {
		const enc = new TextEncoder();
		const parsed = JSON.parse(result);
		const combined = fromBase64(parsed.data);

		const saltLength = parsed.saltLength || SALT_LENGTH;
		const ivLength = parsed.ivLength || IV_LENGTH;
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
				hashLength: ARGON2_HASH_LENGTH,
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
				{ name: 'AES-GCM', length: AES_KEY_LENGTH },
				true,
				['encrypt', 'decrypt']
			);
			keyMaterial = await window.crypto.subtle.exportKey('raw', derivedKey);
		}

		const key = await window.crypto.subtle.importKey(
			'raw',
			new Uint8Array(keyMaterial),
			{ name: 'AES-GCM', length: AES_KEY_LENGTH },
			false,
			['decrypt']
		);

		const decryptedContent = await window.crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv,
				additionalData: enc.encode(ENCRYPTION_AAD)
			},
			key,
			data
		);

		return new TextDecoder().decode(decryptedContent);
	} catch {
		return null;
	}
}
