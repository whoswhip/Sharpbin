import { argon2id } from 'hash-wasm';

self.onmessage = async (event: MessageEvent<Parameters<typeof argon2id>[0]>) => {
	try {
		self.postMessage(await argon2id(event.data));
	} catch {
		self.postMessage(null);
	}
};
