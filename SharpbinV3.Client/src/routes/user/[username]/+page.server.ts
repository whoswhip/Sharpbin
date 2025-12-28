import type { PageServerLoad } from './$types';
import { getServerToken } from '$lib/utils/auth';

export const load: PageServerLoad = async ({ params, fetch, cookies }) => {
    const { username } = params;
    const token = getServerToken(cookies);
    const res = await fetch(`/api/user/${username}`, {
        headers: {
            Authorization: token ? `Bearer ${token}` : ''
        }
    });
    const user = await res.json();
    return { user };
}