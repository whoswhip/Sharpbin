import { apiUrl } from '$lib/server/api';
import { json } from '@sveltejs/kit';

export const GET = async () => {
	const res = await fetch(`${apiUrl}/health`);

	if (!res.ok) {
		return json({ status: 'unhealthy', backend: res.status }, { status: 503 });
	}

	return json({ status: 'ok' });
};
