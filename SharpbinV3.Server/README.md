# SharpbinV3 Server

This is the backend API for SharpbinV3, built with ASP.NET Core and Entity Framework Core.

## Development Setup

### Prerequisites

- .NET 10 SDK
- Entity Framework Core Tools (`dotnet tool install --global dotnet-ef`)

### Configuration

The server configuration is managed in `appsettings.json`. For development, ensure you have set the following in `appsettings.Development.json` or as environment variables:

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
- `PasteSettings__View_HMAC_Secret`: Required to securely hash viewer identifiers
- `PasteSettings__View_Internal_API_Key`: Enforces views to be counted/recorded only by the frontend, if set it needs to be the same for both backend and frontend.

### Database Migrations

Apply the database migrations to initialize the SQLite database:

```bash
dotnet ef database update
```

### Running in Development

Use the following command to run the server with hot reload:

```bash
dotnet watch run
```

The API will be accessible at http://localhost:8080 by default (check `Properties/launchSettings.json` or your specific configuration).

## Tech Stack

- ASP.NET Core (Web API)
- Entity Framework Core with SQLite
- JWT Authentication
- BCrypt for password hashing
- Health Checks for monitoring
- Swagger/OpenAPI for documentation
