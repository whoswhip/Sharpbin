# SharpbinV3 Client

This is the SvelteKit frontend for SharpbinV3.

## Development Setup

### Prerequisites

- Node.js (v20 or newer recommended)
- npm

### Installation

Install the project dependencies:

```bash
npm install
```

### Environment Configuration

The frontend requires an environment variable to point to the backend API. Create a `.env` file in this directory or set the variable in your environment:

- `VITE_API_URL`: The URL of the backend API (e.g., `http://localhost:8080`).
- `VITE_ALLOWED_HOSTS`: A comma separated list of allowed hosts (e.g., `localhost,sharpbin.whoswhip.dev`)
- `VIEW_INTERNAL_API_KEY`: Enforces views to be counted/recorded only by the frontend, if set it needs to be the same for both backend and frontend.

### Running in Development

Start the development server with Hot Module Replacement (HMR):

```bash
npm run dev
```

The frontend will be available at http://localhost:5173.

## Script Reference

- `npm run dev`: Start the Vite development server.
- `npm run build`: Create a production build of the frontend.
- `npm run preview`: Locally preview the production build.
- `npm run check`: Run type checking with svelte-check.
- `npm run lint`: Run ESLint and Prettier checks.
- `npm run format`: Format the codebase with Prettier.