import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

const file = fileURLToPath(new URL('package.json', import.meta.url));
const json = readFileSync(file, 'utf8');
const pkg = JSON.parse(json);

const apiUrl = process.env.VITE_API_URL || 'http://localhost:5050';
const allowedHosts = process.env.VITE_ALLOWED_HOSTS
	? process.env.VITE_ALLOWED_HOSTS.split(',')
	: ['localhost'];

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	define: {
		__APP_VERSION__: JSON.stringify(pkg.version),
		COMMIT_HASH: JSON.stringify(process.env.GIT_COMMIT_HASH || 'unknown')
	},
	server: {
		host: true,
		proxy: {
			'/api': apiUrl,
			'/openapi': apiUrl
		},
		allowedHosts: allowedHosts
	},
	preview: {
		allowedHosts: allowedHosts
	}
});
