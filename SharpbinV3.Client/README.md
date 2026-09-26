# SharpbinV3 Client

This is the SvelteKit frontend for SharpbinV3.

## Development Setup

### Prerequisites

- Node.js 24
- npm

### Installation

Install the project dependencies:

```bash
npm install
```

### Environment Configuration

The frontend defaults to the backend at `http://localhost:5050`. SvelteKit loads `.env` files during development, but `vite.config.ts` reads shell environment variables directly for its proxy and allowed hosts:

- `VITE_API_URL`: The backend URL reachable from the frontend server. Export this in the shell when changing the development backend URL so the Vite proxy and server-side requests use the same value.
- `VITE_ALLOWED_HOSTS`: A comma-separated list of hosts for Vite dev/preview. Export this in the shell before starting Vite. It does not configure the production Node server.

In development, the frontend uses a fixed internal view-recording key matching `appsettings.Development.json`. It ignores `VIEW_INTERNAL_API_KEY` and `View_HMAC_Internal_API_Key` while `NODE_ENV=development`.

### Running in Development

Start the development server with Hot Module Replacement (HMR):

```bash
npm run dev
```

The frontend will be available at http://localhost:5173.

### Running in Production

Docker Compose reads the root `.env` file and runs the built Node server on port 5173. Configure these values there:

- `VITE_API_URL`: Backend URL. Defaults to `http://backend:8080` in Compose.
- `ORIGIN`: Public frontend URL, such as `https://example.com` or `http://localhost:5173` for local Docker testing.
- `PasteSettings__View_Internal_API_Key`: Shared view-recording key. Compose passes it to the frontend as `VIEW_INTERNAL_API_KEY`, so you only set it once.

For a standalone Node deployment, set `VITE_API_URL`, `ORIGIN`, and `VIEW_INTERNAL_API_KEY` in the client's own `.env` file. The key must match the backend's `PasteSettings__View_Internal_API_Key`. The frontend still supports `View_HMAC_Internal_API_Key` as a fallback; it does not read the backend setting name directly.

The standalone server does not load `.env` automatically. Build the frontend, then load your environment file explicitly:

```bash
npm run build
node --env-file=.env build
```

Set `PORT=5173` in that file to use the same port as Docker; the Node adapter otherwise defaults to port 3000. See the [Node adapter documentation](https://svelte.dev/docs/kit/adapter-node#Environment-variables) for runtime configuration.

## Script Reference

- `npm run dev`: Start the Vite development server.
- `npm run build`: Create a production build of the frontend.
- `npm run preview`: Locally preview the production build.
- `npm run check`: Run type checking with svelte-check.
- `npm run lint`: Run ESLint and Prettier checks.
- `npm run format`: Format the codebase with Prettier.
