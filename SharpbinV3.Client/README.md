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

The application requires an environment variable to point to the backend API. Create a `.env` file in this directory or set the variable in your environment:

```env
VITE_API_URL=http://localhost:8080
```

### Running in Development

Start the development server with Hot Module Replacement (HMR):

```bash
npm run dev
```

The application will be available at http://localhost:5173.

## Script Reference

- `npm run dev`: Start the Vite development server.
- `npm run build`: Create a production build of the application.
- `npm run preview`: Locally preview the production build.
- `npm run check`: Run type checking with svelte-check.
- `npm run lint`: Run ESLint and Prettier checks.
- `npm run format`: Format the codebase with Prettier.

## Tech Stack

- Svelte 5 with SvelteKit.
- Tailwind CSS for styling.
- Lucide Svelte for icons.
- Highlight.js for syntax highlighting.
- TypeScript for type safety.
