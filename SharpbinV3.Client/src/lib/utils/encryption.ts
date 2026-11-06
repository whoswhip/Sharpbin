const BASE64_CHUNK_SIZE = 0x8000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const ARGON2_MEMORY_SIZE = 262144;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32;
const AES_KEY_LENGTH = 256;
const ENCRYPTION_AAD = 'enc-v4';
const ENCRYPTED_DATA_OVERHEAD = SALT_LENGTH + IV_LENGTH + 16;
const MAX_ENVELOPE_LENGTH = 16 * 1024 * 1024;
const ENCRYPTION_HEADER = {
	version: 5,
	kdf: 'Argon2id',
	memorySize: ARGON2_MEMORY_SIZE,
	iterations: ARGON2_ITERATIONS,
	parallelism: ARGON2_PARALLELISM,
	algorithm: 'AES-GCM',
	saltLength: SALT_LENGTH,
	ivLength: IV_LENGTH
};
let derivingKey = false;

async function argon2id(
	options: Parameters<typeof import('hash-wasm').argon2id>[0]
): Promise<Uint8Array<ArrayBuffer>> {
	if (derivingKey) throw new Error('Another encryption operation is already running.');
	derivingKey = true;
	try {
		return await new Promise((resolve, reject) => {
			const worker = new Worker(new URL('./argon2.worker.ts', import.meta.url), { type: 'module' });
			const finish = () => {
				clearTimeout(timeout);
				worker.terminate();
			};
			const timeout = setTimeout(() => {
				finish();
				reject(new Error('Key derivation timed out.'));
			}, 60_000);
			worker.onmessage = (event: MessageEvent<Uint8Array | null>) => {
				finish();
				if (event.data instanceof Uint8Array && event.data.length === ARGON2_HASH_LENGTH) {
					resolve(new Uint8Array(event.data));
				} else reject(new Error('Key derivation failed. The device may lack memory.'));
			};
			worker.onerror = (event) => {
				event.preventDefault();
				finish();
				reject(new Error('Unable to run the encryption worker.'));
			};
			try {
				worker.postMessage(options);
			} catch (error) {
				finish();
				reject(error);
			}
		});
	} finally {
		derivingKey = false;
	}
}

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

export function encodePasswordFragment(password: string): string {
	return `u1.${toBase64(new TextEncoder().encode(password))}`;
}

export function decodePasswordFragment(fragment: string): string {
	return fragment.startsWith('u1.')
		? new TextDecoder('utf-8', { fatal: true }).decode(fromBase64(fragment.slice(3)))
		: atob(fragment);
}

export async function encryptAES(content: string, password: string): Promise<string> {
	if (!password) throw new Error('Password required for encryption.');
	if (estimateEncryptedSize(content) > MAX_ENVELOPE_LENGTH) {
		throw new Error('Encrypted paste exceeds the supported size limit.');
	}
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
			additionalData: enc.encode(JSON.stringify(ENCRYPTION_HEADER))
		},
		key,
		enc.encode(content)
	);

	const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength);
	combined.set(salt, 0);
	combined.set(iv, salt.byteLength);
	combined.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);

	return JSON.stringify({
		...ENCRYPTION_HEADER,
		data: toBase64(combined)
	});
}

export function estimateEncryptedSize(content: string): number {
	const rawSize = new TextEncoder().encode(content).length;
	const combinedSize = rawSize + ENCRYPTED_DATA_OVERHEAD;
	const b64Size = Math.ceil(combinedSize / 3) * 4;
	return b64Size + JSON.stringify({ ...ENCRYPTION_HEADER, data: '' }).length;
}

export async function decryptAES(result: string, password: string): Promise<string | null> {
	try {
		const enc = new TextEncoder();
		if (result.length > MAX_ENVELOPE_LENGTH) {
			throw new Error('Encrypted paste exceeds the supported size limit.');
		}
		const parsed = JSON.parse(result);
		if (!parsed || typeof parsed !== 'object' || parsed.algorithm !== 'AES-GCM') {
			throw new Error('Unsupported or malformed encrypted paste.');
		}
		const legacyPBKDF2 =
			parsed.version === 1 &&
			parsed.kdf === 'PBKDF2' &&
			parsed.iterations === 100000 &&
			parsed.hash === 'SHA-256' &&
			(parsed.saltLength === undefined || parsed.saltLength === SALT_LENGTH) &&
			(parsed.ivLength === undefined || parsed.ivLength === IV_LENGTH);
		const legacyArgon2 =
			parsed.version === 4 && parsed.memorySize === 65536 && parsed.saltLength === 32;
		const currentArgon2 =
			(parsed.version === 4 || parsed.version === 5) &&
			parsed.memorySize === ARGON2_MEMORY_SIZE &&
			parsed.saltLength === SALT_LENGTH;
		if (
			!legacyPBKDF2 &&
			!(
				parsed.kdf === 'Argon2id' &&
				parsed.iterations === ARGON2_ITERATIONS &&
				parsed.parallelism === ARGON2_PARALLELISM &&
				parsed.ivLength === IV_LENGTH &&
				(legacyArgon2 || currentArgon2)
			)
		)
			throw new Error('Unsupported encryption profile.');
		if (
			typeof parsed.data !== 'string' ||
			!parsed.data.length ||
			parsed.data.length % 4 !== 0 ||
			!/^[A-Za-z0-9+/]*={0,2}$/.test(parsed.data)
		) {
			throw new Error('Malformed encrypted-paste encoding.');
		}
		const combined = fromBase64(parsed.data);

		const saltLength = parsed.saltLength ?? SALT_LENGTH;
		const ivLength = parsed.ivLength ?? IV_LENGTH;
		if (combined.length < saltLength + ivLength + 16) {
			throw new Error('Encrypted paste is truncated.');
		}
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
				additionalData: enc.encode(
					parsed.version === 5
						? JSON.stringify(ENCRYPTION_HEADER)
						: currentArgon2
							? ENCRYPTION_AAD
							: ''
				)
			},
			key,
			data
		);

		return new TextDecoder().decode(decryptedContent);
	} catch (error) {
		if (error instanceof DOMException && error.name === 'OperationError') return null;
		if (
			error instanceof SyntaxError ||
			(error instanceof DOMException && error.name === 'InvalidCharacterError')
		) {
			throw new Error('Malformed encrypted paste.');
		}
		throw error;
	}
}
