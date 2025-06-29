using Microsoft.Data.Sqlite;
using Newtonsoft.Json.Linq;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;
using System.Security.Cryptography;
using UAParser;
using Microsoft.AspNetCore.RateLimiting;

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
        public static string HMACSecret = "thisneedstobechanged";
        public static JObject Configuration { get; set; }

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
            HMACSecret = Environment.GetEnvironmentVariable("HMAC_SECRET") ?? HMACSecret;
            if (HMACSecret == "thisneedstobechanged")
                logger.LogWarning("HMAC_SECRET is still set to default. Please change this in your .env file.");
            if (HMACSecret.Length < 32 && HMACSecret != "thisneedstobechanged")
                logger.LogWarning("HMAC_SECRET is less than 32 characters. Please change this in your .env file.");
            if (HMACSecret.Length < 6 || HMACSecret.Length <= 0)
            {
                logger.LogError("HMAC_SECRET is less than 6 characters. Please change this in your .env file.");
                Environment.Exit(1);
            }

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = null;
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


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }


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
                context.Response.Headers.Add("Content-Type", "text/html");
                return context.Response.SendFileAsync("wwwroot/index.html");
            }).RequireRateLimiting("general");
            app.MapGet("/{pasteid}", async (HttpContext context, IWebHostEnvironment env) =>
            {
                var pasteid = context.Request.RouteValues["pasteid"].ToString() ?? null;
                if (string.IsNullOrEmpty(pasteid))
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
                            context.Response.Headers.Add("Content-Type", "text/html");
                            break;
                        case "css":
                            context.Response.Headers.Add("Content-Type", "text/css");
                            break;
                        case "js":
                            context.Response.Headers.Add("Content-Type", "text/javascript");
                            break;
                        case "json":
                            context.Response.Headers.Add("Content-Type", "application/json");
                            break;
                        case "png":
                            context.Response.Headers.Add("Content-Type", "image/png");
                            break;
                        case "jpg":
                        case "jpeg":
                            context.Response.Headers.Add("Content-Type", "image/jpeg");
                            break;
                        case "ico":
                            context.Response.Headers.Add("Content-Type", "image/x-icon");
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
                        await Database.AddViewToPaste(null, paste, requestdetails);
                    }
                }
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/paste.html");
            }).RequireRateLimiting("general");
            app.MapGet("/error", async (HttpContext context) =>
            {
                context.Response.StatusCode = 400;
                context.Response.Headers.Add("Content-Type", "text/html");
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
                context.Response.Headers.Add("Content-Type", "text/plain");
                if (paste.FilePath.EndsWith(".gz"))
                {
                    context.Response.Headers.Add("Content-Encoding", "gzip");
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
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/archive.html");
            }).RequireRateLimiting("general");
            app.MapGet("/dash", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/dash.html");
            }).RequireRateLimiting("general");
            app.MapGet("/dash.html", (HttpContext context) =>
            {
                context.Response.Redirect("/dash");
            });
            app.MapGet("/login", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/login.html");
            }).RequireRateLimiting("general");
            app.MapGet("/register", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
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
                context.Response.Headers.Add("Content-Type", "text/html");
                context.Response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate");
                context.Response.Headers.Add("Pragma", "no-cache");
                context.Response.Headers.Add("Expires", "0");


                await context.Response.WriteAsync(html);

            }).RequireRateLimiting("general");
            app.MapGet("/reset-password", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("wwwroot/reset-password.html");
            }).RequireRateLimiting("general");


            #endregion

            #region API

            app.MapPost("/api/accounts/register", async (HttpContext context) =>
            {
                var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
                if (body == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Body." });
                    return;
                }

                var json = TryParse(body);
                if (json == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid JSON." });
                    return;
                }

                var email = json["email"]?.ToString() ?? null;
                var username = json["username"]?.ToString();
                var password = json["password"]?.ToString();

                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }

                var testusername = await Database.UserFromUsername(username);
                if (testusername != null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Username already taken." });
                    return;
                }
                var testemail = await Database.UserFromEmail(email);
                if (testemail != null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Email already in use." });
                    return;
                }

                var passwordHashed = Bcrypt.HashPassword(password, Bcrypt.GenerateSalt(12));
                string token = GenerateToken();
                var requestdetails = GetRequestDetails(context);
                string userUUID = Guid.NewGuid().ToString();

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO users (UUID, Username, Password, Email, Created, LastLogin) VALUES (@UUID, @Username, @Password, @Email, @Created, @LastLogin);";
                        command.Parameters.AddWithValue("@UUID", userUUID);
                        command.Parameters.AddWithValue("@Username", username);
                        command.Parameters.AddWithValue("@Password", passwordHashed);
                        command.Parameters.AddWithValue("@Email", (object)email ?? DBNull.Value);
                        command.Parameters.AddWithValue("@Created", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@LastLogin", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        await command.ExecuteNonQueryAsync();
                    }
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO sessions (UUID, UserUUID, Token, Created, Expirary, Ip, UserAgent) VALUES (@UUID, @UserUUID, @Token, @Created, @Expirary, @Ip, @UserAgent);";
                        command.Parameters.AddWithValue("@UUID", Guid.NewGuid().ToString());
                        command.Parameters.AddWithValue("@UserUUID", userUUID);
                        command.Parameters.AddWithValue("@Token", token);
                        command.Parameters.AddWithValue("@Created", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Expirary", DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Ip", HMAC256HASH(requestdetails.Ip));
                        command.Parameters.AddWithValue("@UserAgent", requestdetails.UserAgent);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds())
                };
                context.Response.Cookies.Append("Authorization", token, cookieOptions);
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Account created." });
                logger.LogInfo($"Account {username} has been created.");
                return;
            }).RequireRateLimiting("auth");
            app.MapPost("/api/accounts/login", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                var __user = await Database.UserFromToken(requestdetails.Token);
                if (!string.IsNullOrEmpty(requestdetails.Token) && __user != null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Already logged in." });
                    return;
                }

                var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
                if (body == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Body." });
                    return;
                }
                var json = TryParse(body);
                if (json == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid JSON." });
                    return;
                }
                var username = json["username"]?.ToString();
                var email = json["email"]?.ToString();
                var password = json["password"]?.ToString();

                if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(email))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }
                if (string.IsNullOrEmpty(password))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }

                User user = null;
                if (!string.IsNullOrEmpty(username))
                    user = await Database.UserFromUsername(username);
                else if (!string.IsNullOrEmpty(email))
                    user = await Database.UserFromEmail(email);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid credentials." });
                    return;
                }
                if (!Bcrypt.Verify(password, user.Password))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid credentials." });
                    return;
                }
                string token = GenerateToken();
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO sessions (UUID, UserUUID, Token, Created, Expirary, Ip, UserAgent) VALUES (@UUID, @UserUUID, @Token, @Created, @Expirary, @Ip, @UserAgent);";
                        command.Parameters.AddWithValue("@UUID", Guid.NewGuid().ToString());
                        command.Parameters.AddWithValue("@UserUUID", user.UUID);
                        command.Parameters.AddWithValue("@Token", token);
                        command.Parameters.AddWithValue("@Created", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Expirary", DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Ip", HMAC256HASH(requestdetails.Ip));
                        command.Parameters.AddWithValue("@UserAgent", requestdetails.UserAgent);
                        await command.ExecuteNonQueryAsync();
                    }
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "UPDATE users SET LastLogin = @LastLogin WHERE UUID = @UUID;";
                        command.Parameters.AddWithValue("@LastLogin", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@UUID", user.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds())
                };
                context.Response.Cookies.Append("Authorization", token, cookieOptions);
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Logged in." });
                logger.LogInfo($"User {user.UUID} logged in.");
                return;
            }).RequireRateLimiting("auth");
            app.MapGet("/api/accounts/authorized", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "No token provided, not authorized." });
                    return;
                }
                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                var cleanuser = new
                {
                    user.UID,
                    user.UUID,
                    user.Username,
                    user.Email,
                    user.DisplayName,
                    user.Created,
                    user.LastLogin,
                    user.Type,
                };
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, user = cleanuser });
                return;
            });
            app.MapPost("/api/accounts/delete", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "No token provided, not authorized." });
                    return;
                }
                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM users WHERE UUID = @UUID;";
                        command.Parameters.AddWithValue("@UUID", user.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM pastes WHERE AuthorUUID = @AuthorUUID;";
                        command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM sessions WHERE UserUUID = @UserUUID;";
                        command.Parameters.AddWithValue("@UserUUID", user.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "UPDATE views SET UserUUID = @UserUUID WHERE UserUUID = @OldUserUUID;";
                        command.Parameters.AddWithValue("@UserUUID", "0");
                        command.Parameters.AddWithValue("@OldUserUUID", user.UUID);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Account deleted." });

            }).RequireRateLimiting("auth");
            app.MapPost("/api/accounts/logout", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "No token provided, not authorized." });
                    return;
                }
                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "DELETE FROM sessions WHERE Token = @Token;";
                        command.Parameters.AddWithValue("@Token", requestdetails.Token);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(-1)
                };
                context.Response.Cookies.Append("Authorization", "", cookieOptions);
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Logged out." });
            });
            app.MapPost("/api/accounts/reset-password", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "No token provided, not authorized." });
                    return;
                }

                var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
                if (body == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Body." });
                    return;
                }
                var json = TryParse(body);
                if (json == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid JSON." });
                    return;
                }
                if (!string.IsNullOrEmpty(json["token"]?.ToString()) && !string.IsNullOrEmpty(json["uuid"]?.ToString()) && !string.IsNullOrEmpty(json["url"]?.ToString()))
                {
                    var password = json["password"]?.ToString();
                    var uuid = json["uuid"]?.ToString();
                    var token = json["token"]?.ToString();
                    var url = json["url"]?.ToString();

                    if (string.IsNullOrEmpty(uuid) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(url) || string.IsNullOrEmpty(password))
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                        return;
                    }

                    var pwreset = await Database.GetPasswordReset(url, uuid, token);
                    if (pwreset == null)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token/url/uuid." });
                        return;
                    }
                    var user = await Database.UserFromUUID(uuid);
                    if (user == null)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid user." });
                        return;
                    }
                    var passwordHashed = Bcrypt.HashPassword(password, Bcrypt.GenerateSalt(12));
                    if (!Database.ResetPassword(user.UUID ?? "", passwordHashed).Result)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Failed to reset password." });
                        return;
                    }
                    else
                    {
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new { success = true, message = "Password reset." });
                    }
                    return;
                }
                else // normal password resets from the dashboard
                {
                    var user = await Database.UserFromToken(requestdetails.Token);
                    if (user == null)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                        return;
                    }
                    var password = json["password"]?.ToString();
                    if (string.IsNullOrEmpty(password))
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                        return;
                    }
                    var passwordHashed = Bcrypt.HashPassword(password, Bcrypt.GenerateSalt(12));
                    if (!Database.ResetPassword(user.UUID ?? "", passwordHashed).Result)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { success = false, message = "Failed to reset password." });
                        return;
                    }
                    else
                    {
                        context.Response.StatusCode = 200;
                        await context.Response.WriteAsJsonAsync(new { success = true, message = "Password reset." });
                    }
                }
            }).RequireRateLimiting("auth");


            app.MapPost("/api/pastes/create", async (HttpContext context) =>
            {
                var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
                if (body == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Body." });
                    return;
                }
                if (body.Length > MaxFileSize)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "File size too large." });
                    return;
                }

                var paste = new Paste();
                var requestdetails = GetRequestDetails(context);
                var user = await Database.UserFromToken(requestdetails.Token);
                var queries = context.Request.Query;

                if (queries.ContainsKey("title") && queries["title"].ToString().Length > 500)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Title too long." });
                    return;
                }


                paste.Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                paste.Size = body.Length;
                paste.TrueSize = body.Length;
                paste.UUID = Guid.NewGuid().ToString();
                paste.ID = GenerateRandomString(12);
                paste.AuthorUUID = user?.UUID ?? "0"; // 0 means the user is anonymous
                paste.FilePath = $"pastes/{paste.ID}.txt";
                paste.Visibility = queries.ContainsKey("visibility") ? Convert.ToInt32(queries["visibility"]) : 0;
                paste.Title = queries.ContainsKey("title") && !string.IsNullOrEmpty(queries["title"].ToString()) ? queries["title"].ToString() : $"Untitled-{await Database.EnumeratePastes()}";
                paste.Edited = 0;
                paste.Views = 0;
                paste.Syntax = queries.ContainsKey("syntax") ? queries["syntax"].ToString() : null;

                if (!string.IsNullOrEmpty(paste.Syntax) && !ValidSyntaxLanguages.Contains(paste.Syntax.ToLower()))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid syntax language." });
                    return;
                }

                bool shouldCompress = await Compression.ShouldCompress(body);
                if (shouldCompress)
                {
                    var compressed = await Compression.CompressString(body);
                    paste.Size = compressed.Length;
                    paste.TrueSize = body.Length;
                    paste.FilePath += ".gz";
                    await File.WriteAllBytesAsync(paste.FilePath, compressed);
                }
                else
                {
                    await File.WriteAllTextAsync(paste.FilePath, body);
                }

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO pastes (UUID, ID, Visibility, Title, AuthorUUID, FilePath, Created, Edited, Size, TrueSize, Views, Syntax) VALUES (@UUID, @ID, @Visibility, @Title, @AuthorUUID, @FilePath, @Created, @Edited, @Size, @TrueSize, @Views, @Syntax);";
                        command.Parameters.AddWithValue("@UUID", paste.UUID);
                        command.Parameters.AddWithValue("@ID", paste.ID);
                        command.Parameters.AddWithValue("@Visibility", paste.Visibility);
                        command.Parameters.AddWithValue("@Title", paste.Title);
                        command.Parameters.AddWithValue("@AuthorUUID", paste.AuthorUUID);
                        command.Parameters.AddWithValue("@FilePath", paste.FilePath);
                        command.Parameters.AddWithValue("@Created", paste.Created);
                        command.Parameters.AddWithValue("@Edited", paste.Edited);
                        command.Parameters.AddWithValue("@Size", paste.Size);
                        command.Parameters.AddWithValue("@TrueSize", paste.TrueSize);
                        command.Parameters.AddWithValue("@Views", paste.Views);
                        command.Parameters.AddWithValue("@Syntax", paste.Syntax);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }
                paste.FilePath = null;
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Paste created.", paste = paste });
                logger.LogInfo($"A Paste of {FormatBytes(paste.Size ?? 0)} was created by {paste.UUID}");
                return;
            }).RequireRateLimiting("uploads");
            app.MapGet("/api/pastes/archive", async (HttpContext context) =>
            {
                var queries = context.Request.Query;
                if (!queries.ContainsKey("page") && !queries.ContainsKey("limit"))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }
                var page = queries.ContainsKey("page") ? Convert.ToInt32(queries["page"]) : 0;
                var limit = queries.ContainsKey("limit") ? Convert.ToInt32(queries["limit"]) : 10;
                int pages = await Database.EnumeratePastes() / limit;

                if (page < 0 || limit <= 0 || limit > 25)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid page or limit." });
                    return;
                }
                if (page > pages)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Page out of range.", pages });
                    return;
                }

                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM pastes WHERE Visibility NOT IN (1, 2) ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";
                        command.Parameters.AddWithValue("@Limit", limit);
                        command.Parameters.AddWithValue("@Offset", page * limit);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                            {
                                context.Response.StatusCode = 400;
                                await context.Response.WriteAsJsonAsync(new { success = false, message = "No pastes found." });
                                return;
                            }
                            var pastes = new List<object>();
                            while (await reader.ReadAsync())
                            {
                                pastes.Add(new
                                {
                                    UUID = reader.GetString(1),
                                    ID = reader.GetString(2),
                                    Visibility = reader.GetInt32(3),
                                    Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    AuthorUUID = reader.GetString(5),
                                    Created = reader.GetInt64(7),
                                    Edited = reader.GetInt64(8),
                                    Size = reader.GetInt32(9),
                                    TrueSize = reader.GetInt32(10),
                                    Views = reader.GetInt32(11),
                                    Syntax = reader.IsDBNull(12) ? null : reader.GetString(12)
                                });
                            }

                            context.Response.StatusCode = 200;
                            await context.Response.WriteAsJsonAsync(new { success = true, pastes, pages });
                            return;
                        }
                    }
                }
            }).RequireRateLimiting("general");
            app.MapGet("/api/pastes/my", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Not authorized." });
                    return;
                }

                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                var queries = context.Request.Query;
                if (!queries.ContainsKey("page") && !queries.ContainsKey("limit"))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }
                var page = queries.ContainsKey("page") ? Convert.ToInt32(queries["page"]) : 0;
                var limit = queries.ContainsKey("limit") ? Convert.ToInt32(queries["limit"]) : 10;
                if (page < 0 || limit <= 0 || limit > 25)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid page or limit." });
                    return;
                }
                int pages = await Database.EnumerateUserPastes(user) / limit;
                if (page > pages)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Page out of range.", pages });
                    return;
                }
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM pastes WHERE AuthorUUID = @AuthorUUID ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";
                        command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                        command.Parameters.AddWithValue("@Limit", limit);
                        command.Parameters.AddWithValue("@Offset", page * limit);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                            {
                                context.Response.StatusCode = 400;
                                await context.Response.WriteAsJsonAsync(new { success = false, error = true, message = "No pastes found." });
                                return;
                            }
                            var pastes = new List<Paste>();
                            while (await reader.ReadAsync())
                            {
                                pastes.Add(new Paste
                                {
                                    UUID = reader.GetString(1),
                                    ID = reader.GetString(2),
                                    Visibility = reader.GetInt32(3),
                                    Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    AuthorUUID = reader.GetString(5),
                                    Created = reader.GetInt64(7),
                                    Edited = reader.GetInt64(8),
                                    Size = reader.GetInt32(9),
                                    TrueSize = reader.GetInt32(10),
                                    Views = reader.GetInt32(11),
                                    Syntax = reader.IsDBNull(12) ? null : reader.GetString(12)
                                });
                            }

                            context.Response.StatusCode = 200;
                            await context.Response.WriteAsJsonAsync(new { success = true, pastes, pages });
                            return;
                        }
                    }
                }

            });
            app.MapGet("/api/pastes/{pasteid}/info", async (HttpContext context) =>
            {
                var pasteid = context.Request.RouteValues["pasteid"].ToString() ?? null;
                if (string.IsNullOrEmpty(pasteid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Paste ID." });
                    return;
                }
                var paste = await Database.GetPasteFromID(pasteid);
                string authorUsername = null;
                if (paste == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Paste not found." });
                    return;
                }
                if (paste.AuthorUUID != "0")
                {
                    var user = await Database.UserFromUUID(paste.AuthorUUID);
                    authorUsername = user?.Username;
                }
                else
                {
                    paste.AuthorUUID = "Anonymous";
                    authorUsername = "Anonymous";
                }
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    paste = new
                    {
                        paste.UUID,
                        paste.ID,
                        paste.Visibility,
                        paste.Title,
                        paste.AuthorUUID,
                        username = authorUsername,
                        paste.Created,
                        paste.Edited,
                        paste.Size,
                        paste.TrueSize,
                        paste.Views,
                        paste.Syntax
                    }
                });
            }).RequireRateLimiting("general");
            app.MapGet("/api/pastes/{pasteid}", async (HttpContext context) =>
            {
                var pasteid = context.Request.RouteValues["pasteid"].ToString() ?? null;
                if (string.IsNullOrEmpty(pasteid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Paste ID." });
                    return;
                }
                var paste = await Database.GetPasteFromID(pasteid);
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/plain");
                if (paste.FilePath.EndsWith(".gz"))
                {
                    context.Response.Headers.Add("Content-Encoding", "gzip");
                    await context.Response.SendFileAsync(paste.FilePath);
                }
                else
                {
                    await context.Response.SendFileAsync(paste.FilePath);
                }
                return;
            }).RequireRateLimiting("general");
            app.MapGet("/api/pastes/{pasteid}/views", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                var pasteid = context.Request.RouteValues["pasteid"].ToString() ?? null;
                if (string.IsNullOrEmpty(pasteid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Paste ID." });
                    return;
                }
                if (string.IsNullOrEmpty(requestdetails.Token))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Not authorized. Please provide a token." });
                    return;
                }
                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                var paste = await Database.GetPasteFromID(pasteid);
                if (paste == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Paste not found." });
                    return;
                }
                if (paste.AuthorUUID != user.UUID)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "You are not the author of this paste." });
                    return;
                }
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM views WHERE PasteUUID = @PasteUUID;";
                        command.Parameters.AddWithValue("@PasteUUID", paste.UUID);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                            {
                                context.Response.StatusCode = 400;
                                await context.Response.WriteAsJsonAsync(new { success = false, message = "No views found." });
                                return;
                            }
                            var views = new List<object>();
                            var uaparser = Parser.GetDefault();
                            int viewcount = 0;

                            while (await reader.ReadAsync())
                            {
                                viewcount++;
                                string useragent = reader.GetString(3);
                                var clientInfo = uaparser.Parse(useragent);
                                views.Add(new
                                {
                                    PasteUUID = reader.GetString(1),
                                    Created = reader.GetInt64(4),
                                    UserAgent = new
                                    {
                                        browser = clientInfo.UA.Family,
                                        platform = clientInfo.OS.Family,
                                        device = clientInfo.Device.Family,
                                    }
                                });
                            }
                            context.Response.StatusCode = 200;
                            await context.Response.WriteAsJsonAsync(new { success = true, views, viewcount });

                        }
                    }
                }

            }).RequireRateLimiting("general");

            app.MapGet("/api/users/uuid/{uuid}", async (HttpContext context) =>
            {
                var uuid = context.Request.RouteValues["uuid"].ToString() ?? null;
                if (string.IsNullOrEmpty(uuid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid UUID." });
                    return;
                }
                var user = await Database.UserFromUUID(uuid);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "User not found." });
                    return;
                }

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin
                    }
                });
            }).RequireRateLimiting("general");
            app.MapGet("/api/users/{username}", async (HttpContext context) =>
            {
                var username = context.Request.RouteValues["username"].ToString() ?? null;
                if (string.IsNullOrEmpty(username))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid Username." });
                    return;
                }
                var user = await Database.UserFromUsername(username);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "User not found." });
                    return;
                }
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = true,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin
                    }
                });
            }).RequireRateLimiting("general");
            app.MapGet("/api/users/{uuid}/pastes", async (HttpContext context) =>
            {
                var uuid = context.Request.RouteValues["uuid"].ToString() ?? null;
                if (string.IsNullOrEmpty(uuid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid UUID." });
                    return;
                }
                var user = await Database.UserFromUUID(uuid);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "User not found." });
                    return;
                }
                var queries = context.Request.Query;
                if (!queries.ContainsKey("page") && !queries.ContainsKey("limit"))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Missing required fields." });
                    return;
                }
                var page = queries.ContainsKey("page") ? Convert.ToInt32(queries["page"]) : 0;
                var limit = queries.ContainsKey("limit") ? Convert.ToInt32(queries["limit"]) : 10;
                if (page < 0 || limit <= 0 || limit > 25)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid page or limit." });
                    return;
                }
                int pages = await Database.EnumerateUserPastes(user) / limit;
                if (page > pages)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Page out of range.", pages });
                    return;
                }
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT * FROM pastes WHERE AuthorUUID = @AuthorUUID AND Visibility NOT IN (1, 2) ORDER BY Created DESC LIMIT @Limit OFFSET @Offset;";
                        command.Parameters.AddWithValue("@AuthorUUID", user.UUID);
                        command.Parameters.AddWithValue("@Limit", limit);
                        command.Parameters.AddWithValue("@Offset", page * limit);
                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!reader.HasRows)
                            {
                                context.Response.StatusCode = 400;
                                await context.Response.WriteAsJsonAsync(new { success = false, error = true, message = "No pastes found." });
                                return;
                            }
                            var pastes = new List<Paste>();
                            while (await reader.ReadAsync())
                            {
                                pastes.Add(new Paste
                                {
                                    UUID = reader.GetString(1),
                                    ID = reader.GetString(2),
                                    Visibility = reader.GetInt32(3),
                                    Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    AuthorUUID = reader.GetString(5),
                                    Created = reader.GetInt64(7),
                                    Edited = reader.GetInt64(8),
                                    Size = reader.GetInt32(9),
                                    TrueSize = reader.GetInt32(10),
                                    Views = reader.GetInt32(11),
                                    Syntax = reader.IsDBNull(12) ? null : reader.GetString(12)
                                });
                            }

                            context.Response.StatusCode = 200;
                            await context.Response.WriteAsJsonAsync(new { success = true, pastes, pages });
                            return;
                        }
                    }

                }
            }).RequireRateLimiting("general");

            app.MapGet("/api/site/info", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                var info = new
                {
                    MaxFileSize
                };
                await context.Response.WriteAsJsonAsync(new { success = true, info });
            }).RequireRateLimiting("general");

            app.MapGet("/admin/{useruuid}/reset-password", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                var user = await Database.UserFromToken(requestdetails.Token);
                if (user == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid token." });
                    return;
                }
                if (user.Type != 255)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Not authorized." });
                    return;
                }

                var useruuid = context.Request.RouteValues["useruuid"].ToString() ?? null;
                if (string.IsNullOrEmpty(useruuid))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Invalid UUID." });
                    return;
                }
                var targetuser = await Database.UserFromUUID(useruuid);
                if (targetuser == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "User not found." });
                    return;
                }
                string uuid = Guid.NewGuid().ToString();
                string url = GenerateRandomString(32);
                string token = GenerateToken();
                using (var connection = new SqliteConnection(MainDatabaseConnection))
                {
                    await connection.OpenAsync();
                    var expiry = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
                    using (var command = connection.CreateCommand())
                    {
                        command.CommandText = "INSERT INTO passwordresets (UUID, USERUUID, URL, Token,Created, Expirary) VALUES (@UUID, @USERUUID, @URL, @Token,@Created, @Expirary);";
                        command.Parameters.AddWithValue("@UUID", uuid);
                        command.Parameters.AddWithValue("@USERUUID", targetuser.UUID);
                        command.Parameters.AddWithValue("@URL", url);
                        command.Parameters.AddWithValue("@Token", token);
                        command.Parameters.AddWithValue("@Created", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                        command.Parameters.AddWithValue("@Expirary", expiry);
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }
                var resetlink = $"{context.Request.Scheme}://{context.Request.Host}/reset-password?uuid={uuid}&url={url}&token={token}";

                context.Response.StatusCode = 200;

                context.Response.Headers.Add("Content-Type", "application/json");
                await context.Response.WriteAsJsonAsync(new { success = true, resetlink, uuid, url, token });
            });


            #endregion

            await app.RunAsync();

        }

        #region Helper Functions
        static JObject TryParse(string json)
        {
            try
            {
                return JObject.Parse(json);
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        static JArray TryParseArray(string json)
        {
            try
            {
                return JArray.Parse(json);
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        static string GenerateToken()
        {
            string randomstring = GenerateRandomString(32);
            string randomguid = Guid.NewGuid().ToString();
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(Bcrypt.HashPassword(randomstring + randomguid, Bcrypt.GenerateSalt(10))));
        }
        static string GenerateRandomString(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
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
        static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }
        public static string HMAC256HASH(string data)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(HMACSecret)))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToBase64String(hashBytes);
            }
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