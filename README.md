# SharpbinV3

Sharpbin is a [pastebin](https://en.wikipedia.org/wiki/Pastebin)-style website built with ASP.NET Core and SvelteKit.

A live instance is available at [sharpbin.cc](https://sharpbin.cc).

## Features

- User authentication and account management.
- Syntax highlighting for various programming languages.
- Private pastes with client-side encryption.
- Raw text serving for easy sharing and scripting.
- Paste editing including content, syntax, title, and expiration.
- Configurable paste expiration.
- Server-side paste compression to save storage.
- Captcha support via Cloudflare Turnstile.

## Getting Started

The easiest way to run SharpbinV3 is using Docker Compose.

1. Ensure Docker and Docker Compose are installed.
2. Clone the repository.

```bash
git clone https://github.com/whoswhip/Sharpbin.git
```

3. In the repository root, copy `backend.env.example` to `backend.env` and `frontend.env.example` to `frontend.env`.
4. Replace the secret placeholders and configure your domain and Turnstile keys. Set `ORIGIN` to the public frontend URL, including the scheme. For local Docker testing, use `ORIGIN=http://localhost:5173`, `Domain=localhost:5173`, `Https=false`, and `AllowedCorsOrigins__0=http://localhost:5173`.
5. Run the following command in the root directory:

```bash
docker compose up -d --build
```

### Configuration

Configure the backend in `backend.env` and the frontend in `frontend.env` when using Docker Compose. The backend also loads `appsettings.json`, with environment variables taking precedence.

Compose explicitly sets `ConnectionStrings__DefaultConnection`, `DATA_PROTECTION_KEY_PATH`, and the frontend's `VITE_API_URL`. These override values from the environment files; change `docker-compose.yml` to override them.

The example secrets are placeholders, not secure defaults. Generate a separate secret for JWT signing, API-key hashing, and view hashing, plus one shared internal API key. This command generates a 64-character random hex value; run it once for each secret:

```bash
docker run --rm node:24-alpine node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

or use openSSL:

```bash
openssl rand -hex 32
```

Set the same shared value in `PasteSettings__View_Internal_API_Key` in `backend.env` and `VIEW_INTERNAL_API_KEY` in `frontend.env`. Keep generated secrets across restarts and updates. Changing the API-key HMAC secret invalidates existing API keys.

> When configuring via `appsettings.json` instead of for example `ConnectionStrings__DefaultConnection` it would be:

```json
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=sharpbin.db"
  },
```

#### Backend (SharpbinV3.Server)

- `Domain`: The domain your instance of Sharpbin will be hosted at (e.g., example.com)
- `Https`: Whether the public instance uses HTTPS. Used when generating email links; this does not enable TLS on the server.
- `AllowedCorsOrigins__0`: An allowed browser origin for the backend API (e.g., `https://example.com`). Use numbered entries for additional origins.
- `ConnectionStrings__DefaultConnection`: SQLite connection string (e.g., `Data Source=/app/data/sharpbin.db`).
- `JwtSettings__Secret`: A random secret of 32-128 characters used for signing JWT tokens.
- `AuthSettings__CF_Turnstile_SecretKey`: Your Cloudflare Turnstile secret key.
- `AuthSettings__CF_Turnstile_SiteKey`: Your Cloudflare Turnstile site key.
- `AuthSettings__Registration_Enabled`:**true**: Enables/disables registration.
- `AuthSettings__First_User_Admin`: Gives the first user the admin role, it is recommended to disable this after use.
- `AuthSettings__Admins_Require_2FA`: Enforces Admins to have 2FA when trying to do certain actions.
- `AuthSettings__API_Key_HMAC_Secret`: Recommended to securely hash API keys, but is not required.
- `PasteSettings__MaxTitleLength`: Max title length in characters.
- `PasteSettings__MaxPasteSizeInBytes`:**1_048_576** (1MB): Max Paste Size set in bytes.
- `PasteSettings__EnablePasteCompression`:**true**: Enables/Disables server-side paste compression.
- `PasteSettings__RequiresVerification`:**true**: Enables/Disables CAPTCHA verification when creating pastes.
- `PasteSettings__View_HMAC_Secret`: A required random secret of 32–128 characters used to hash viewer identifiers.
- `PasteSettings__View_Internal_API_Key`: A shared key of 32–128 characters used to authorize view recording. Match the frontend's `VIEW_INTERNAL_API_KEY`.

#### Frontend (SharpbinV3.Client)

- `VITE_API_URL`: The backend URL reachable from the frontend server. Defaults to `http://localhost:5050`; Compose overrides it with `http://backend:8080`. Browser requests use the frontend's `/api` proxy.
- `ORIGIN`: The public frontend URL, including its scheme (e.g., `https://example.com`). Used by the production Node server; see [SvelteKit's Node adapter documentation](https://svelte.dev/docs/kit/adapter-node#ORIGIN-PROTOCOL_HEADER-HOST_HEADER-and-PORT_HEADER).
- `VITE_ALLOWED_HOSTS`: A comma-separated list used only by Vite dev/preview (e.g., `localhost,sharpbin.cc`). Export it in the shell before starting Vite; the config reads `process.env` directly. It does not configure production host restrictions.
- `VIEW_INTERNAL_API_KEY`: The production frontend's shared view-recording key. Falls back to `View_HMAC_Internal_API_Key` if unset. The frontend does not read `PasteSettings__View_Internal_API_Key`.

When `NODE_ENV=development`, the frontend uses a fixed development-only internal key matching the backend's checked-in development configuration and ignores both environment key names. See the [client README](SharpbinV3.Client/README.md) for development and standalone production setup.

The frontend will be accessible at http://localhost:5173.

## Project Structure

- **[SharpbinV3.Server](SharpbinV3.Server/README.md)**: Backend API built with C# and ASP.NET Core. Refer to its README for server-side development and configuration.
- **[SharpbinV3.Client](SharpbinV3.Client/README.md)**: Frontend application built with SvelteKit and TypeScript. Refer to its README for client-side development and setup.
