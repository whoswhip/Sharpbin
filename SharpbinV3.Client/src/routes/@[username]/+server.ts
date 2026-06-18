import { error, redirect } from '@sveltejs/kit';

export async function GET({ params }) {
	const username = params?.username;
	if (!username) throw error(404, 'User not found');
	throw redirect(302, `/user/${encodeURIComponent(username)}`);
}
