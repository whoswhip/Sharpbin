# SharpbinV3 Server

This is the backend API for SharpbinV3, built with ASP.NET Core and Entity Framework Core.

## Development Setup

### Prerequisites

- .NET 10 SDK
- Entity Framework Core Tools (`dotnet tool install --global dotnet-ef`)

### Configuration

The server configuration is managed in `appsettings.json`. For development, ensure you have set the following in `appsettings.Development.json` or as environment variables:

- `ConnectionStrings__DefaultConnection`: SQLite connection string (e.g., `Data Source=sharpbin.db` locally). Compose defaults to `Data Source=/app/data/sharpbin.db`.
- `JwtSettings__Secret`: A random secret of 32–128 characters used for signing JWT tokens.
- `PasteSettings__View_HMAC_Secret`: A required random secret of 32–128 characters used to hash viewer identifiers.
- `PasteSettings__View_Internal_API_Key`: A shared key of 32–128 characters used to authorize view recording. Compose passes it to both services. For standalone deployments, match the frontend's `VIEW_INTERNAL_API_KEY`.

For Docker Compose, configure the backend in the root `.env` file. The image includes `appsettings.json` defaults, and environment variables override them. No host configuration mount is required.

The development frontend uses a fixed internal key matching the checked-in `appsettings.Development.json`. Changing only the backend key will break development view recording. Use generated secrets for deployment; see the [root configuration guide](../README.md#configuration).

### Database Migrations

The backend applies database migrations automatically on startup. To apply them manually before starting it:

```bash
dotnet ef database update
```

### Running in Development

Use the following command to run the server with hot reload:

```bash
dotnet watch run
```

The API will be accessible at http://localhost:5050 by default (check `Properties/launchSettings.json` or your specific configuration).
