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

3. In the repository root, copy `.env.example` to `.env`.
4. Replace the secret placeholders and configure your domain and Turnstile keys. Set `ORIGIN` to the public frontend URL, including the scheme. For local Docker testing, use `ORIGIN=http://localhost:5173`, `Domain=localhost:5173`, `Https=false`, and `AllowedCorsOrigins__0=http://localhost:5173`.
5. Run the following command in the root directory:

```bash
docker compose up -d --build
```

### Configuration

Configure Sharpbin in the root `.env` file when using Docker Compose. The backend loads this file as environment variables. Compose passes only the backend URL, public origin, and shared view-recording key to the frontend.

The backend image includes `appsettings.json` with application defaults. Environment variables have priority, so you do not need to edit or mount that file for normal setup. Additional backend settings, including `EmailSettings__Host` and other SMTP settings, can be added to `.env` using their existing names.

Compose defaults the database to `/app/data/sharpbin.db`, Data Protection keys to `/app/data/keys`, and `VITE_API_URL` to `http://backend:8080`. To override them, add `ConnectionStrings__DefaultConnection`, `DATA_PROTECTION_KEY_PATH`, or `VITE_API_URL` to `.env`. Keep database and key paths under `/app/data` to use the existing persistent volume.

The example secrets are placeholders, not secure defaults. Generate a separate secret for JWT signing, API-key hashing, and view hashing, plus one shared internal API key. This command generates a 64-character random hex value; run it once for each secret:

```bash
docker run --rm node:24-alpine node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

or use openSSL:

```bash
openssl rand -hex 32
```

Set the shared key once as `PasteSettings__View_Internal_API_Key`. Compose supplies it to the frontend as `VIEW_INTERNAL_API_KEY`. Keep generated secrets across restarts and updates. Changing the API-key HMAC secret invalidates existing API keys.

#### Migrating an Existing Installation

1. Copy the values from `backend.env` into the root `.env` file. If `.env` already exists, merge the settings without replacing existing values blindly.
2. Copy `ORIGIN` from `frontend.env`. If it was unset, use your public frontend URL, including the scheme.
3. Keep `PasteSettings__View_Internal_API_Key` set to the existing shared key. The separate `VIEW_INTERNAL_API_KEY` entry is no longer needed for Compose.
4. Move any custom `appsettings.json` values into `.env` using `__` for nested settings. For array settings, use numbered entries such as `AllowedCorsOrigins__0`. If you need to retain a custom JSON file, add a read-only mount for it in `compose.override.yaml`.
5. Run `docker compose up -d --build`. The old `backend.env` and `frontend.env` files are no longer read by Compose.

Keep the existing database volume, Data Protection keys, and secret values. Do not regenerate secrets during this migration.

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
- `PasteSettings__View_Internal_API_Key`: A shared key of 32–128 characters used to authorize view recording. Compose passes it to both services.

#### Frontend (SharpbinV3.Client)

- `VITE_API_URL`: The backend URL reachable from the frontend server. Defaults to `http://localhost:5050` when running directly and `http://backend:8080` in Compose. Browser requests use the frontend's `/api` proxy.
- `ORIGIN`: The public frontend URL, including its scheme (e.g., `https://example.com`). Used by the production Node server; see [SvelteKit's Node adapter documentation](https://svelte.dev/docs/kit/adapter-node#ORIGIN-PROTOCOL_HEADER-HOST_HEADER-and-PORT_HEADER).
- `VITE_ALLOWED_HOSTS`: A comma-separated list used only by Vite dev/preview (e.g., `localhost,sharpbin.cc`). Export it in the shell before starting Vite; the config reads `process.env` directly. It does not configure production host restrictions.
- `VIEW_INTERNAL_API_KEY`: The production frontend's shared view-recording key. Compose sets it from `PasteSettings__View_Internal_API_Key`; do not duplicate it in the root `.env`. When running the frontend directly, set it yourself or use the existing `View_HMAC_Internal_API_Key` fallback.

When `NODE_ENV=development`, the frontend uses a fixed development-only internal key matching the backend's checked-in development configuration and ignores both environment key names. See the [client README](SharpbinV3.Client/README.md) for development and standalone production setup.

The frontend will be accessible at http://localhost:5173.

## Project Structure

- **[SharpbinV3.Server](SharpbinV3.Server/README.md)**: Backend API built with C# and ASP.NET Core. Refer to its README for server-side development and configuration.
- **[SharpbinV3.Client](SharpbinV3.Client/README.md)**: Frontend application built with SvelteKit and TypeScript. Refer to its README for client-side development and setup.
