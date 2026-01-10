using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Server.Authorization;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Services.Verification.Providers;
using SharpbinV3.Server.Settings;
using System.Text;
using System.Threading.RateLimiting;

namespace SharpbinV3.Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();
            builder.Services.AddDbContext<AppDbContext>(opt =>
            {
                opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
            });
            builder.Services.AddSingleton<ICompressionService, CompressionService>();
            builder.Services.AddSingleton<IHostedService, PasteCleanUpService>();
            builder.Services.AddSingleton<IHostedService, PasteViewCleanUpService>();
            builder.Services.AddScoped<UserService>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<PasteService>();
            builder.Services.AddScoped<VerificationService>();
            builder.Services.AddScoped<TotpVerificationProvider>();
            builder.Services.AddHttpClient<IVerificationProvider, TurnstileVerificationProvider>();
            builder.Services.AddMemoryCache();

            builder.Services.AddHealthChecks()
                .AddDbContextCheck<AppDbContext>("Database");

            builder.Services.AddOptions<PasteSettings>()
                .Bind(builder.Configuration.GetSection("PasteSettings"))
                .ValidateDataAnnotations()
                .ValidateOnStart();
            builder.Services.AddOptions<JWTSettings>()
                .Bind(builder.Configuration.GetSection("JwtSettings"))
                .ValidateDataAnnotations()
                .ValidateOnStart();
            builder.Services.Configure<AuthSettings>(builder.Configuration.GetSection("AuthSettings"));

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer();

            builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
                .Configure<IOptions<JWTSettings>>((options, jwtSettings) =>
                {
                    var settings = jwtSettings.Value;
                    var key = Encoding.UTF8.GetBytes(settings.Secret);

                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),

                        ValidateIssuer = true,
                        ValidIssuer = settings.Issuer,

                        ValidateAudience = true,
                        ValidAudience = settings.Audience,

                        RequireExpirationTime = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,

                        RequireSignedTokens = true,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    };
                });

            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("NotBanned", policy =>
                    policy.Requirements.Add(new NotBannedRequirement()));
            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("AuthAndNotBanned", policy =>
                    policy.Requirements.Add(new NotBannedRequirement()));
            builder.Services.AddSingleton<IAuthorizationHandler>(new NotBannedHandler(false));
            builder.Services.AddSingleton<IAuthorizationHandler>(new NotBannedHandler(true));


            builder.Services.AddRateLimiter(options =>
            {
                options.AddSlidingWindowLimiter("Sliding", opt =>
                {
                    opt.Window = TimeSpan.FromSeconds(10);
                    opt.PermitLimit = 10;
                    opt.QueueLimit = 2;
                    opt.SegmentsPerWindow = 5;
                    opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                });

                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            });
            builder.Services.AddCors(o =>
            {
                o.AddDefaultPolicy(p =>
                    p.WithOrigins("http://localhost:5173")
                     .AllowAnyHeader()
                     .AllowAnyMethod());
            });

            builder.Services.AddDataProtection()
                .PersistKeysToFileSystem(GetDataProtectionKeyDirectory(builder.Environment))
                .SetApplicationName("SharpbinV3");

            var app = builder.Build();
            app.UseRateLimiter();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                db.Database.Migrate();

                // this is temporary since the migration doesnt seem to work properly
                db.Database.ExecuteSql($"""
                    CREATE TRIGGER IF NOT EXISTS Users_UID_AutoIncrement
                    AFTER INSERT ON Users
                    BEGIN
                        UPDATE Users
                        SET UID = (
                            SELECT IFNULL(MAX(UID), 0) + 1 FROM Users
                        )
                        WHERE rowid = NEW.rowid AND NEW.UID IS NULL;
                    END;
                    """);
            }

            app.MapHealthChecks("/health");

            app.Run();
        }
        static DirectoryInfo GetDataProtectionKeyDirectory(IHostEnvironment env)
        {
            var overridepath = Environment.GetEnvironmentVariable("DATA_PROTECTION_KEY_PATH");
            if (!string.IsNullOrEmpty(overridepath))
                return new DirectoryInfo(overridepath);

            var basePath = env.IsDevelopment()
                ? Environment.CurrentDirectory
                : Environment.SpecialFolder.ApplicationData.ToString();

            var path = Path.Combine(basePath, "SharpbinV3", "DataProtectionKeys");

            return new DirectoryInfo(path);
        }
    }
}
