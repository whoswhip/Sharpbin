using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using SharpbinV3.Server.Authentication;
using SharpbinV3.Server.Authorization;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Services.Verification.Providers;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            DotEnv.Load(".env");
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder
                .Services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
                    options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
                });
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi(options =>
            {
                options.AddDocumentTransformer(
                    (document, context, cancellationToken) =>
                    {
                        document?.Components ??= new();
                        document?.Servers?.Clear();
                        document?.Components?.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();

                        document
                            ?.Components
                            ?.SecuritySchemes
                            ?["ApiKey"] = new OpenApiSecurityScheme
                            {
                                Type = SecuritySchemeType.ApiKey,
                                Name = "X-API-Key",
                                In = ParameterLocation.Header,
                                Description = "Bypass authentication and captcha by providing a valid API key.",
                            };

                        return Task.CompletedTask;
                    }
                );
            });

            builder.Services.AddDbContext<AppDbContext>(opt =>
            {
                opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
            });
            builder.Services.AddSingleton<ICompressionService, CompressionService>();
            builder.Services.AddSingleton<IHostedService, PasteCleanUpService>();
            builder.Services.AddSingleton<IHostedService, PasteViewCleanUpService>();
            builder.Services.AddSingleton<EmailService>();
            builder.Services.AddSingleton<IHostedService>(sp => sp.GetRequiredService<EmailService>());
            builder.Services.AddScoped<UserService>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<PasteService>();
            builder.Services.AddScoped<CommentService>();
            builder.Services.AddScoped<ApiKeyService>();
            builder.Services.AddScoped<VerificationService>();
            builder.Services.AddScoped<TotpVerificationProvider>();
            builder.Services.AddHttpClient<IVerificationProvider, TurnstileVerificationProvider>();
            builder.Services.AddScoped<ReportService>();
            builder.Services.AddMemoryCache();
            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddHealthChecks().AddDbContextCheck<AppDbContext>("Database");

            builder
                .Services.AddOptions<PasteSettings>()
                .Bind(builder.Configuration.GetSection("PasteSettings"))
                .ValidateDataAnnotations()
                .ValidateOnStart();
            builder
                .Services.AddOptions<JWTSettings>()
                .Bind(builder.Configuration.GetSection("JwtSettings"))
                .ValidateDataAnnotations()
                .ValidateOnStart();
            builder.Services.AddOptions<AppSettings>().Bind(builder.Configuration).ValidateDataAnnotations().ValidateOnStart();
            builder.Services.AddOptions<AuthSettings>().Bind(builder.Configuration.GetSection("AuthSettings")).ValidateDataAnnotations();
            builder.Services.AddOptions<EmailSettings>().Bind(builder.Configuration.GetSection("EmailSettings")).ValidateDataAnnotations();

            builder
                .Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AuthSchemes.Combined;
                    options.DefaultScheme = AuthSchemes.Combined;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddPolicyScheme(
                    AuthSchemes.Combined,
                    AuthSchemes.Combined,
                    options =>
                    {
                        options.ForwardDefaultSelector = context =>
                        {
                            var apiKeyHeader = context.Request.Headers["X-API-Key"].ToString();
                            if (!string.IsNullOrEmpty(apiKeyHeader))
                                return AuthSchemes.ApiKey;

                            var authHeader = context.Request.Headers.Authorization.ToString();
                            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                                return JwtBearerDefaults.AuthenticationScheme;

                            return JwtBearerDefaults.AuthenticationScheme;
                        };
                    }
                )
                .AddJwtBearer()
                .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(AuthSchemes.ApiKey, _ => { });

            builder
                .Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
                .Configure<IOptions<JWTSettings>>(
                    (options, jwtSettings) =>
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
                            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                        };
                    }
                );

            builder.Services.AddAuthorizationBuilder().AddPolicy("NotBanned", policy => policy.Requirements.Add(new NotBannedRequirement()));
            builder.Services.AddAuthorizationBuilder().AddPolicy("AuthAndNotBanned", policy => policy.Requirements.Add(new NotBannedRequirement()));
            builder
                .Services.AddAuthorizationBuilder()
                .AddPolicy(
                    "JwtOnly",
                    policy =>
                    {
                        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                        policy.RequireAuthenticatedUser();
                    }
                );
            builder
                .Services.AddAuthorizationBuilder()
                .AddPolicy(
                    "JwtOnlyAndNotBanned",
                    policy =>
                    {
                        policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                        policy.RequireAuthenticatedUser();
                        policy.Requirements.Add(new NotBannedRequirement());
                    }
                );
            builder.Services.AddSingleton<IAuthorizationHandler>(new NotBannedHandler(false));
            builder.Services.AddSingleton<IAuthorizationHandler>(new NotBannedHandler(true));

            builder.Services.AddRateLimiter(options =>
            {
                options.AddPolicy(
                    "Sliding",
                    httpContext =>
                        RateLimitPartition.GetSlidingWindowLimiter(
                            httpContext.GetRequestIP(),
                            _ => new SlidingWindowRateLimiterOptions
                            {
                                Window = TimeSpan.FromSeconds(10),
                                PermitLimit = 10,
                                QueueLimit = 2,
                                SegmentsPerWindow = 5,
                                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            }
                        )
                );

                options.AddPolicy(
                    "Strict",
                    httpContext =>
                        RateLimitPartition.GetTokenBucketLimiter(
                            httpContext.GetRequestIP(),
                            _ => new TokenBucketRateLimiterOptions
                            {
                                TokenLimit = 8,
                                QueueLimit = 0,
                                TokensPerPeriod = 1,
                                ReplenishmentPeriod = TimeSpan.FromSeconds(30),
                                AutoReplenishment = true,
                                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            }
                        )
                );

                options.AddPolicy(
                    "Sensitive",
                    httpContext =>
                        RateLimitPartition.GetTokenBucketLimiter(
                            httpContext.GetRequestIP(),
                            _ => new TokenBucketRateLimiterOptions
                            {
                                TokenLimit = 5,
                                QueueLimit = 0,
                                TokensPerPeriod = 1,
                                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                                AutoReplenishment = true,
                                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            }
                        )
                );

                options.AddPolicy("NoLimit", _ => RateLimitPartition.GetNoLimiter(0));

                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
                {
                    var remoteIp = httpContext.GetRequestIP();

                    return RateLimitPartition.GetFixedWindowLimiter(
                        remoteIp,
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 120,
                            Window = TimeSpan.FromMinutes(1),
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0,
                        }
                    );
                });

                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.OnRejected = async (context, cancellationToken) =>
                {
                    await context.HttpContext.Response.WriteAsJsonAsync(
                        new { success = false, Message = "Too many requests. Please try again later." },
                        cancellationToken: cancellationToken
                    );
                };
            });
            builder.Services.AddOutputCache(options =>
            {
                options.AddPolicy(
                    "1Day",
                    builder =>
                    {
                        builder.Expire(TimeSpan.FromDays(1));
                    }
                );
            });

            builder.Services.AddCors(o =>
            {
                var allowedOrigins =
                    builder.Configuration.GetSection(nameof(AppSettings.AllowedCorsOrigins)).Get<string[]>() ?? ["http://localhost:5173"];
                o.AddDefaultPolicy(p => p.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod());
            });

            builder
                .Services.AddDataProtection()
                .PersistKeysToFileSystem(GetDataProtectionKeyDirectory(builder.Environment))
                .SetApplicationName("SharpbinV3");

            var app = builder.Build();
            app.UseRateLimiter();

            if (app.Environment.IsDevelopment())
                app.MapOpenApi();

            app.UseHttpsRedirection();
            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseOutputCache();

            app.MapControllers();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                db.Database.Migrate();
            }

            app.MapHealthChecks("/health");

            app.MapGet(
                    "/api/stats",
                    async (AppDbContext db) =>
                    {
                        var now = DateTimeOffset.UtcNow;
                        var todayStart = new DateTimeOffset(now.Year, now.Month, now.Day, 0, 0, 0, TimeSpan.Zero);
                        var sevenDaysAgo = todayStart.AddDays(-6).ToUnixTimeMilliseconds();

                        var pasteCount = await db.Pastes.CountAsync();
                        var userCount = await db.Users.CountAsync();
                        var totalStoredSize = await db.Pastes.SumAsync(p => p.StoredSize);
                        var totalOriginalSize = await db.Pastes.SumAsync(p => p.OriginalSize);

                        var dailyCounts = await db
                            .Pastes.Where(p => p.CreatedAt >= sevenDaysAgo)
                            .GroupBy(p => p.CreatedAt / 86400000)
                            .Select(g => new { Day = g.Key, Count = g.Count() })
                            .ToDictionaryAsync(x => x.Day, x => x.Count);

                        var dailyStats = new List<object>();
                        var pasteCountWeek = 0;

                        for (int i = 6; i >= 0; i--)
                        {
                            var dayTs = todayStart.AddDays(-i).ToUnixTimeMilliseconds();
                            dailyCounts.TryGetValue(dayTs / 86400000, out var count);

                            dailyStats.Add(new { date = dayTs, count });
                            pasteCountWeek += count;
                        }

                        return Results.Ok(
                            new
                            {
                                success = true,
                                stats = new
                                {
                                    pastes = new
                                    {
                                        total = pasteCount,
                                        past7Days = pasteCountWeek,
                                        totalStoredSizeInBytes = totalStoredSize,
                                        totalOriginalSizeInBytes = totalOriginalSize,
                                        daily = dailyStats,
                                    },
                                    users = new { total = userCount },
                                },
                            }
                        );
                    }
                )
                .CacheOutput(policy => policy.Expire(TimeSpan.FromHours(6)).Tag("stats"));

            app.Run();
        }

        static DirectoryInfo GetDataProtectionKeyDirectory(IHostEnvironment env)
        {
            var overridepath = Environment.GetEnvironmentVariable("DATA_PROTECTION_KEY_PATH");
            if (!string.IsNullOrEmpty(overridepath))
                return new DirectoryInfo(overridepath);

            var basePath = env.IsDevelopment() ? Environment.CurrentDirectory : Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var path = Path.Combine(basePath, "SharpbinV3", "DataProtectionKeys");

            return new DirectoryInfo(path);
        }
    }
}
