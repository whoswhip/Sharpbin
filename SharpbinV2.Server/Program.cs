using Microsoft.Data.Sqlite;
using Newtonsoft.Json.Linq;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;
using UAParser;
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
            builder.Services.AddControllers();
            builder.Services.AddScoped<DatabaseService>();


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

            app.MapControllers();

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