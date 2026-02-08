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

The API will be accessible at http://localhost:5050 by default (check `Properties/launchSettings.json` or your specific configuration).