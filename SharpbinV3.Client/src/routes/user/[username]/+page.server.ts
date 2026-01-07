import type { PageServerLoad } from './$types';
import { getServerToken } from '$lib/utils/auth';
import type { User } from '$lib/types/user';

const apiUrl = process.env.VITE_API_URL || 'http://localhost:5050';

export const load: PageServerLoad = async ({ params, fetch, cookies, url }) => {
	const { username } = params;
	const token = getServerToken(cookies);

	const res = await fetch(`${apiUrl}/api/user/${username}`, {
		headers: {
			Authorization: token ? `Bearer ${token}` : ''
		}
	});

	if (res.status === 500) {
		return {
			status: 500,
			error: { message: 'Internal server error' }
		};
	}

	const json = await res.json();

	if (res.status !== 200) {
		return {
			status: res.status,
			error: { message: json.message || 'An error occurred' }
		};
	}
	const user = json as User;
	return { user, url: url.href };
};
