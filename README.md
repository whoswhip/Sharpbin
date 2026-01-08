# SharpbinV3

Sharpbin is a pastebin-style website built with ASP.NET Core and SvelteKit.

## Features

- User authentication and account management.
- Syntax highlighting for various programming languages.
- Private pastes with client-side encryption.
- Raw text serving for easy sharing and scripting.
- Paste editing including content, syntax, title, and expiration.
- Configurable paste expiration.
- Server-side paste compression to save storage.
- Captcha support via Cloudflare Turnstile.

## Project Structure

- **[SharpbinV3.Server](SharpbinV3.Server/README.md)**: Backend API built with C# and ASP.NET Core. Refer to its README for server-side development and configuration.
- **[SharpbinV3.Client](SharpbinV3.Client/README.md)**: Frontend application built with SvelteKit and TypeScript. Refer to its README for client-side development and setup.

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

You can configure the application using environment variables. When using Docker Compose, these can be set in the `docker-compose.yml` file.

#### Backend (SharpbinV3.Server)

- `ConnectionStrings__DefaultConnection`: SQLite connection string (e.g., `Data Source=/app/data/sharpbin.db`).
- `JwtSettings__Secret`: A secure string used for signing JWT tokens.
- `AuthSettings__CF_Turnstile_SecretKey`: Your Cloudflare Turnstile secret key.
- `AuthSettings__CF_Turnstile_SiteKey`: Your Cloudflare Turnstile site key.
- `AuthSettings__Registration_Enabled`: Set to `true` by default, enables/disables registration. 
- `AuthSettings__First_User_Admin`: Gives the first user the admin role, it is recommended to disable this after use.
- `AuthSettings__Admins_Require_2FA`: Enforces Admins to have 2FA when trying to do certain actions.
- `PasteSettings__MaxTitleLength`: Max title length in characters.
- `PasteSettings__MaxPasteSizeInBytes`: Max Paste Size set in bytes, the default is `1_048_576` (1MB)
- `PasteSettings__EnablePasteCompression`: Enables/Disables server-side paste compression, `true` by default.
- `PasteSettings__RequiresVerification`: Enables/Disables CAPTCHA verification when creating pastes, `true` by default.
- `ASPNETCORE_ENVIRONMENT`: Set to `Production` or `Development`.

#### Frontend (SharpbinV3.Client)

- `VITE_API_URL`: The URL of the backend API (e.g., `http://localhost:8080`).
- `VITE_ALLOWED_HOSTS`: A comma separated list of allowed hosts (e.g., `localhost,sharpbin.whoswhip.dev`)

The frontend will be accessible at http://localhost:5173.
