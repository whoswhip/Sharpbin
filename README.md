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

3. Run the following command in the root directory:

```bash
docker-compose up -d
```

### Configuration

You can configure Sharpbin using environment variables or `appsettings.json`. When using Docker Compose, these can be set in the `docker-compose.yml` file.

> When configuring via `appsettings.json` instead of for example `ConnectionStrings__DefaultConnection` it would be:

```json
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=sharpbin.db"
  },
```

#### Backend (SharpbinV3.Server)

- `ConnectionStrings__DefaultConnection`: SQLite connection string (e.g., `Data Source=/app/data/sharpbin.db`).
- `JwtSettings__Secret`: A secure string used for signing JWT tokens.
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
- `PasteSettings__View_HMAC_Secret`: Required to securely hash viewer identifiers
- `PasteSettings__View_Internal_API_Key`: Enforces views to be counted/recorded only by the frontend, if set it needs to be the same for both backend and frontend.

#### Frontend (SharpbinV3.Client)

- `VITE_API_URL`: The URL of the backend API (e.g., `http://localhost:8080`).
- `VITE_ALLOWED_HOSTS`: A comma separated list of allowed hosts (e.g., `localhost,sharpbin.cc`)
- `VIEW_INTERNAL_API_KEY`: Enforces views to be counted/recorded only by the frontend, if set it needs to be the same for both backend and frontend.

The frontend will be accessible at http://localhost:5173.

## Project Structure

- **[SharpbinV3.Server](SharpbinV3.Server/README.md)**: Backend API built with C# and ASP.NET Core. Refer to its README for server-side development and configuration.
- **[SharpbinV3.Client](SharpbinV3.Client/README.md)**: Frontend application built with SvelteKit and TypeScript. Refer to its README for client-side development and setup.
