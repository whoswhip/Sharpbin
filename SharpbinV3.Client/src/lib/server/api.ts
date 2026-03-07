import { env } from '$env/dynamic/private';

export const apiUrl = env.VITE_API_URL ?? 'http://localhost:5050';
export const viewInternalApiKey =
	env.NODE_ENV === 'development'
		? 'cccdd42d9f2f648493e402f1da7c855ea798ad510e6bb9ea712dd7bed838e58'
		: (env.VIEW_INTERNAL_API_KEY ?? env.View_HMAC_Internal_API_Key ?? '');
