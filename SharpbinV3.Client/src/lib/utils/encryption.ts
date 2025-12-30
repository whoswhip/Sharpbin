export async function encryptAES(content: string, password: string): Promise<string> {
	const enc = new TextEncoder();
	const keyMaterial = await window.crypto.subtle.importKey(
		'raw',
		enc.encode(password),
		{ name: 'PBKDF2' },
		false,
		['deriveBits', 'deriveKey']
	);
	const salt = window.crypto.getRandomValues(new Uint8Array(16));
	const key = await window.crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 100000,
			hash: 'SHA-256'
		},
		keyMaterial,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt']
	);
	const iv = window.crypto.getRandomValues(new Uint8Array(12));
	const encryptedContent = await window.crypto.subtle.encrypt(
		{
			name: 'AES-GCM',
			iv: iv
		},
		key,
		enc.encode(content)
	);
	const combined = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength);
	combined.set(salt, 0);
	combined.set(iv, salt.byteLength);
	combined.set(new Uint8Array(encryptedContent), salt.byteLength + iv.byteLength);
	const result = {
		version: 1,
		kdf: 'PBKDF2',
		iterations: 100000,
		hash: 'SHA-256',
		algorithm: 'AES-GCM',
		data: btoa(String.fromCharCode(...combined))
	};
	return JSON.stringify(result);
}

export async function decryptAES(result: string, password: string): Promise<string | null> {
	try {
		const enc = new TextEncoder();
		const parsed = JSON.parse(result);
		const combined = Uint8Array.from(atob(parsed.data), (c) => c.charCodeAt(0));
		const salt = combined.slice(0, 16);
		const iv = combined.slice(16, 28);
		const data = combined.slice(28);
		const keyMaterial = await window.crypto.subtle.importKey(
			'raw',
			enc.encode(password),
			{ name: 'PBKDF2' },
			false,
			['deriveBits', 'deriveKey']
		);
		const key = await window.crypto.subtle.deriveKey(
			{
				name: 'PBKDF2',
				salt: salt,
				iterations: parsed.iterations,
				hash: parsed.hash
			},
			keyMaterial,
			{ name: 'AES-GCM', length: 256 },
			false,
			['decrypt']
		);
		const decryptedContent = await window.crypto.subtle.decrypt(
			{
				name: 'AES-GCM',
				iv: iv
			},
			key,
			data
		);
		const dec = new TextDecoder();
		return dec.decode(decryptedContent);
	} catch {
		return null;
	}
}
