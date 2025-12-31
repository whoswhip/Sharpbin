import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const apiUrl = process.env.VITE_API_URL || 'http://localhost:5050';
const allowedHosts = process.env.VITE_ALLOWED_HOSTS
	? process.env.VITE_ALLOWED_HOSTS.split(',')
	: ['localhost'];

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/api': apiUrl
		}
	},
	preview: {
		allowedHosts: allowedHosts
	}
});
