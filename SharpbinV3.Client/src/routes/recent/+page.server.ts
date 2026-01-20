import type { PageServerLoad } from './$types';
import type { Paste } from '$lib/types/paste';
import { extractError } from '$lib/utils/misc';

export const load: PageServerLoad = async ({ fetch }) => {
    try {
        const res = await fetch('/api/paste/recent');
        if (!res.ok) {
            const errorMsg = extractError(await res.json()) || 'Failed to fetch recent pastes.';
            throw new Error(errorMsg);
        }
        const recentPastes: Paste[] = await res.json();
        return { recentPastes };
    }
    catch (error) {
        console.error(error);
        return { recentPastes: [] };
    }
};
