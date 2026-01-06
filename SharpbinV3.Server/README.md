# SharpbinV3 Server

This is the backend API for SharpbinV3, built with ASP.NET Core and Entity Framework Core.

## Development Setup

### Prerequisites

- .NET 10 SDK
- Entity Framework Core Tools (`dotnet tool install --global dotnet-ef`)

### Configuration

The server configuration is managed in `appsettings.json`. For development, ensure you have set the following in `appsettings.Development.json` or as environment variables:

- `ConnectionStrings:DefaultConnection`: The SQLite connection string (e.g., `Data Source=sharpbin.db`).
- `JwtSettings:Secret`: A secure key for JWT signing.
- `CloudflareSettings:TurnstileSecret`: Your Cloudflare Turnstile secret key (if using captcha).

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
