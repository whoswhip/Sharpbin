using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV2.Server.Models;
using SharpbinV2.Server.Services;

namespace SharpbinV2.Server
{
    class Program
    {
        public static string MainDatabaseConnection = "Data Source=data.db";
        public static long MaxFileSize = 1_048_576; // 1MB
        public static string[] ValidSyntaxLanguages =
        {
            "none",
            "autoHotkey",
            "autoIt",
            "bash",
            "c",
            "cpp",
            "csharp",
            "css",
            "dart",
            "html",
            "java",
            "javascript",
            "json",
            "lua",
            "markdown",
            "php",
            "python",
            "ruby",
            "rust",
            "sql",
            "swift",
            "typescript",
            "toml",
            "xml"
        };

        static async Task Main(string[] args)
        {
            await Initialize();
            var logger = new Logging();
            var builder = WebApplication.CreateBuilder(args);
            builder.Configuration.AddEnvironmentVariables();
            if (Environment.GetEnvironmentVariable("HTTPS") == "true")
            {
                builder.WebHost.UseUrls($"https://*:{Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORTS") ?? "5820"}");
            }
            else
            {
                builder.WebHost.UseUrls($"http://*:{Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS") ?? "5810"}");
            }
            MaxFileSize = Environment.GetEnvironmentVariable("MAX_FILE_SIZE") != null ? Convert.ToInt64(Environment.GetEnvironmentVariable("MAX_FILE_SIZE")) : MaxFileSize;

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = MaxFileSize;
            });

            builder.Services.AddRateLimiter(options =>
            {
                options.AddTokenBucketLimiter("uploads", opt =>
                {
                    opt.TokenLimit = 10;
                    opt.ReplenishmentPeriod = TimeSpan.FromMinutes(1);
                    opt.TokensPerPeriod = 2;
                    opt.AutoReplenishment = true;
                });

                options.AddTokenBucketLimiter("auth", opt =>
                {
                    opt.TokenLimit = 15;
                    opt.ReplenishmentPeriod = TimeSpan.FromMinutes(5);
                    opt.TokensPerPeriod = 10;
                    opt.AutoReplenishment = true;
                });

                options.AddFixedWindowLimiter("general", opt =>
                {
                    opt.PermitLimit = 200;
                    opt.Window = TimeSpan.FromMinutes(1);
                });

                options.OnRejected = async (context, token) =>
                {
                    context.HttpContext.Response.StatusCode = 429;
                    await context.HttpContext.Response.WriteAsJsonAsync(new
                    {
                        success = false,
                        message = "Rate limit exceeded. Please try again later."
                    });
                };
            });


            // Add services to the container.
            builder.Services.AddCors();
            builder.Services.AddResponseCaching();
            builder.Services.AddResponseCompression();
            builder.Services.AddControllers();
            builder.Services.AddScoped<DatabaseService>();
            //builder.Services.AddEndpointsApiExplorer();
            //builder.Services.AddSwaggerGen();


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();

            }

            //if (app.Environment.IsDevelopment())
            //{
            //    app.UseSwagger();
            //    app.UseSwaggerUI();
            //}


            //app.UseHttpsRedirection();
            app.UseRouting();
            app.UseStaticFiles();

            app.UseRateLimiter();

            app.UseCors(builder =>
            {
                builder.AllowAnyOrigin();
                builder.AllowAnyMethod();
                builder.AllowAnyHeader();
            });
            app.UseResponseCaching();
            app.UseResponseCompression();

            #region Static Endpoints
            app.MapGet("/", (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                return context.Response.SendFileAsync("wwwroot/index.html");
            }).RequireRateLimiting("general");
            app.MapGet("/{pasteid}", async (HttpContext context, IWebHostEnvironment env, string pasteid) =>
            {
                if (string.IsNullOrWhiteSpace(pasteid))
                {
                    context.Response.StatusCode = 400;
                    context.Response.Redirect("/error?error=400&message=Invalid paste id.");
                    return;
                }

                var filePath = Path.Combine(env.WebRootPath, pasteid);
                if (File.Exists(filePath))
                {
                    context.Response.StatusCode = 200;
                    switch (Path.GetExtension(filePath))
                    {
                        case "html":
                            context.Response.Headers.Append("Content-Type", "text/html");
                            break;
                        case "css":
                            context.Response.Headers.Append("Content-Type", "text/css");
                            break;
                        case "js":
                            context.Response.Headers.Append("Content-Type", "text/javascript");
                            break;
                        case "json":
                            context.Response.Headers.Append("Content-Type", "application/json");
                            break;
                        case "png":
                            context.Response.Headers.Append("Content-Type", "image/png");
                            break;
                        case "jpg":
                        case "jpeg":
                            context.Response.Headers.Append("Content-Type", "image/jpeg");
                            break;
                        case "ico":
                            context.Response.Headers.Append("Content-Type", "image/x-icon");
                            break;
                    }
                    await context.Response.SendFileAsync(filePath);
                    return;
                }
                var paste = await Database.GetPasteFromID(pasteid);
                if (paste == null)
                {
                    context.Response.StatusCode = 400;
                    context.Response.Redirect("/error?error=400&message=Paste not found.");
                    return;
                }
                var requestdetails = GetRequestDetails(context);
                var user = await Database.UserFromToken(requestdetails.Token);

                if (user != null)
                {
                    if (user.UUID != paste.AuthorUUID)
                    {
                        if (!await Database.HasAlreadyViewedFromUserDetails(user))
                        {
                            await Database.AddViewToPaste(user, paste, requestdetails);
                        }
                    }
                }
                else
                {
                    if (!await Database.HasAlreadyViewedFromRqDetails(requestdetails))
                    {
                        await Database.AddViewToPaste(new User { UUID = "0" }, paste, requestdetails);
                    }
                }
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/paste.html");
            }).RequireRateLimiting("general");
            app.MapGet("/error", async (HttpContext context) =>
            {
                context.Response.StatusCode = 400;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/error.html");
            });
            app.MapGet("/error.html", (HttpContext context) =>
            {
                context.Response.Redirect("/error");
            });
            app.MapGet("/raw/{pasteid}", async (HttpContext context) =>
            {
                var pasteid = context.Request.RouteValues["pasteid"].ToString() ?? null;
                if (string.IsNullOrEmpty(pasteid))
                {
                    context.Response.StatusCode = 400;
                    context.Response.Redirect("/error?error=400&message=Invalid paste id.");
                    return;
                }
                var paste = await Database.GetPasteFromID(pasteid);
                if (paste == null)
                {
                    context.Response.StatusCode = 400;
                    context.Response.Redirect("/error?error=400&message=Paste not found.");
                    return;
                }
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/plain");
                if (paste.FilePath.EndsWith(".gz"))
                {
                    context.Response.Headers.Append("Content-Encoding", "gzip");
                    await context.Response.SendFileAsync(paste.FilePath);
                }
                else
                {
                    await context.Response.SendFileAsync(paste.FilePath);
                }
            }).RequireRateLimiting("general");
            app.MapGet("/paste.html", (HttpContext context) =>
            {
                context.Response.Redirect("/");
            });
            app.MapGet("/archive", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/archive.html");
            }).RequireRateLimiting("general");
            app.MapGet("/dash", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/dash.html");
            }).RequireRateLimiting("general");
            app.MapGet("/dash.html", (HttpContext context) =>
            {
                context.Response.Redirect("/dash");
            });
            app.MapGet("/login", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/login.html");
            }).RequireRateLimiting("general");
            app.MapGet("/register", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/register.html");
            }).RequireRateLimiting("general");
            app.MapGet("/u/{username}", async (HttpContext context) =>
            {
                var username = context.Request.RouteValues["username"].ToString() ?? null;
                if (string.IsNullOrEmpty(username))
                {
                    context.Response.StatusCode = 400;
                    context.Response.Redirect("/error?error=400&message=Invalid username.");
                    return;
                }
                string html = File.ReadAllText("wwwroot/user.html");
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                context.Response.Headers.Append("Cache-Control", "no-cache, no-store, must-revalidate");
                context.Response.Headers.Append("Pragma", "no-cache");
                context.Response.Headers.Append("Expires", "0");


                await context.Response.WriteAsync(html);

            }).RequireRateLimiting("general");
            app.MapGet("/reset-password", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Append("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/reset-password.html");
            }).RequireRateLimiting("general");
            #endregion

            app.MapControllers();

            await app.RunAsync();

        }

        #region Helper Functions
        static RequestDetails GetRequestDetails(HttpContext context)
        {
            var requestdetails = new RequestDetails();
            var headers = context.Request.Headers;
            if (headers.ContainsKey("User-Agent"))
                requestdetails.UserAgent = headers["User-Agent"];

            if (headers.ContainsKey("X-Forwarded-For"))
                requestdetails.Ip = headers["X-Forwarded-For"];
            else if (headers.ContainsKey("X-Real-IP"))
                requestdetails.Ip = headers["X-Real-IP"];
            else if (headers.ContainsKey("CF-Connecting-IP"))
                requestdetails.Ip = headers["CF-Connecting-IP"];
            else if (headers.ContainsKey("True-Client-IP"))
                requestdetails.Ip = headers["True-Client-IP"];
            else if (headers.ContainsKey("X-Cluster-Client-IP"))
                requestdetails.Ip = headers["X-Cluster-Client-IP"];
            else if (headers.ContainsKey("X-ProxyUser-IP"))
                requestdetails.Ip = headers["X-ProxyUser-IP"];
            else
                requestdetails.Ip = context.Connection.RemoteIpAddress?.ToString();

            if (headers.ContainsKey("Authorization"))
                requestdetails.Token = headers["Authorization"];
            else if (context.Request.Cookies.ContainsKey("Authorization"))
                requestdetails.Token = context.Request.Cookies["Authorization"];

            return requestdetails;
        }
        #endregion
        static async Task Initialize()
        {
            try
            {
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS users (
                                UID INTEGER UNIQUE,
                                UUID TEXT NOT NULL UNIQUE,
                                Type INTEGER NOT NULL DEFAULT 0,
                                Email TEXT UNIQUE,
                                Username TEXT NOT NULL UNIQUE,
                                DisplayName TEXT,
                                Password TEXT NOT NULL,
                                Created INTEGER NOT NULL,
                                LastLogin INTEGER,
                                PRIMARY KEY(UID AUTOINCREMENT)
                            );";
                        await command.ExecuteNonQueryAsync();
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS pastes (
	                            UID	INTEGER NOT NULL UNIQUE,
	                            UUID	TEXT NOT NULL UNIQUE,
                                ID TEXT NOT NULL UNIQUE,
	                            Visibility	INTEGER,
	                            Title	TEXT,
	                            AuthorUUID	TEXT NOT NULL,
	                            FilePath	TEXT NOT NULL UNIQUE,
	                            Created	INTEGER NOT NULL,
	                            Edited	INTEGER,
	                            Size	INTEGER NOT NULL,
                                TrueSize	INTEGER NOT NULL,
                                Views	INTEGER NOT NULL DEFAULT 0,
                                Syntax TEXT,
	                            PRIMARY KEY(UID AUTOINCREMENT)
                            );";
                        await command.ExecuteNonQueryAsync();
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS sessions (
	                            UUID	TEXT NOT NULL UNIQUE,
	                            UserUUID	INTEGER NOT NULL,
	                            Token	INTEGER NOT NULL UNIQUE,
	                            Created	INTEGER NOT NULL,
	                            Expirary	INTEGER NOT NULL,
	                            Ip	TEXT NOT NULL,
	                            UserAgent	TEXT NOT NULL
                            );";
                        await command.ExecuteNonQueryAsync();
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS views (
                                UserUUID	TEXT NOT NULL,
                                PasteUUID	INTEGER NOT NULL,
                                Ip	TEXT NOT NULL,
                                UserAgent	TEXT NOT NULL,
                                Created	INTEGER NOT NULL
                            );";
                        await command.ExecuteNonQueryAsync();
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS punishments (
                                UID INTEGER NOT NULL UNIQUE,
                                UUID TEXT NOT NULL UNIQUE,
                                Type INTEGER NOT NULL DEFAULT 0,
                                Reason TEXT,
                                Created INTEGER NOT NULL,
                                Expirary INTEGER NOT NULL,
                                PRIMARY KEY(UID AUTOINCREMENT)
                            );";
                        await command.ExecuteNonQueryAsync();
                        command.CommandText = @"CREATE TABLE IF NOT EXISTS passwordresets (
                                UID INTEGER NOT NULL UNIQUE,
                                UUID TEXT NOT NULL UNIQUE,
                                USERUUID TEXT NOT NULL UNIQUE,
                                URL TEXT NOT NULL UNIQUE,
                                Token TEXT NOT NULL UNIQUE,
                                Created INTEGER NOT NULL,
                                Expirary INTEGER NOT NULL,
                                PRIMARY KEY(UID AUTOINCREMENT)
                            );";
                        await command.ExecuteNonQueryAsync();
                        await connection.CloseAsync();
                    }
                }
                if (!Directory.Exists("pastes"))
                    Directory.CreateDirectory("pastes");
                if (!Directory.Exists("logs"))
                    Directory.CreateDirectory("logs");
                var root = Directory.GetCurrentDirectory();
                var dotenv = Path.Combine(root, ".env");
                DotEnv.Load(dotenv);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Environment.Exit(1);
            }
        }
    }




    /// <summary>
    /// https://dusted.codes/dotenv-in-dotnet
    /// </summary>
    public static class DotEnv
    {
        public static void Load(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            foreach (var line in File.ReadAllLines(filePath))
            {
                var parts = line.Split(
                    '=',
                    StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length != 2)
                    continue;

                Environment.SetEnvironmentVariable(parts[0], parts[1]);
            }
        }
    }
}