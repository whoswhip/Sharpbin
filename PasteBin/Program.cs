using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using System.Threading.RateLimiting;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Text;
using Sharpbin;


class Program
{
    private static string cfTurnstileSiteKey = string.Empty;
    public static string cfTurnstileSecret = string.Empty;

    public static Dictionary<int, string> accountType = new Dictionary<int, string>
    {
        { 0, "User" },
        { 8, "Early Access" },
        { 9, "Hour One"},
        { 255, "Admin" }
    };
    public static Dictionary<int, string> accountState = new Dictionary<int, string>
    {
        { 0, "Active" },
        { 1, "Banned" },
        { 2, "Suspended" }
    };

    public static async Task Main(string[] args)
    {
        await InitializeAsync();

        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorPages();
        builder.Services.AddCors();
        builder.Services.AddResponseCaching();
        builder.Services.AddResponseCompression();


        builder.Services.AddRateLimiter(_ => _
        .AddFixedWindowLimiter(policyName: "OneRequest", options =>
        {
            options.PermitLimit = 1;
            options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            options.QueueLimit = 2;
        }));
        builder.Services.AddRateLimiter(_ => _
        .AddFixedWindowLimiter(policyName: "fixed", options =>
        {
            options.PermitLimit = 4;
            options.Window = TimeSpan.FromSeconds(12);
            options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            options.QueueLimit = 2;
        }));
        builder.Services.AddRateLimiter(_ => _
        .AddFixedWindowLimiter(policyName: "fixed-bigger", options =>
        {
            options.PermitLimit = 8;
            options.Window = TimeSpan.FromSeconds(6);
            options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            options.QueueLimit = 4;
        }));
        builder.Services.AddRateLimiter(_ => _
        .AddFixedWindowLimiter(policyName: "fixed-xl", options =>
        {
            options.PermitLimit = 16;
            options.Window = TimeSpan.FromSeconds(6);
            options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
            options.QueueLimit = 4;
        }));
        builder.Services.AddRateLimiter(options =>
        {
            options.AddPolicy("OneRequestPerIP", context =>
                RateLimitPartition.GetConcurrencyLimiter(context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown", key => new ConcurrencyLimiterOptions
                {
                    PermitLimit = 1,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 1
                }));
        });

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }


        //app.UseHttpsRedirection();
        app.UseStaticFiles();
        
        app.UseRouting();

        app.UseRateLimiter();

        app.UseCors(builder =>
        {
            builder.AllowAnyOrigin();
            builder.AllowAnyMethod();
            builder.AllowAnyHeader();
        });
        app.UseAuthorization();
        app.UseResponseCaching();
        app.UseResponseCompression();

        app.MapRazorPages();

        #region Frontend

        app.MapGet("/", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets/index.html");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                var user = await GetLoggedInUserAsync(context?.Request?.Cookies?["token"]);
                if (user.State != 0)
                {
                    var punishment = await GetPunishmentAsync(user.UUID);
                    var unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();
                    if (punishment.ExpirationDate > unixNow)
                    {
                        context.Response.Redirect("/banned");
                        return;
                    }
                    else
                    {
                        await UnbanUUIDAsync(user.UUID);
                    }
                }
                html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a> ");
            }
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;
        });
        app.MapGet("/favicon.ico", async (HttpContext context) =>
        {
            context.Response.ContentType = "image/x-icon";
            if (!File.Exists("assets/favicon.ico"))
            {
                context.Response.StatusCode = 404;
                return;
            }
            await context.Response.SendFileAsync("assets/favicon.ico");
            return;
        });
        app.MapGet("/login", async (HttpContext context) =>
        {
            if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/");
                return;
            }
            var html = File.ReadAllText("assets/login.html");
            html = html.Replace("{html}", "<a href=\"/sign-up\">sign up</a>");
            html = html.Replace("{sitekey}", cfTurnstileSiteKey);
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;
        });
        app.MapGet("/sign-up", async (HttpContext context) =>
        {
            if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/");
                return;
            }
            var html = File.ReadAllText("assets/signup.html");
            html = html.Replace("{html}", "<a href=\"/login\">login</a>");
            html = html.Replace("{sitekey}", cfTurnstileSiteKey);
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;
        });
        app.MapGet("/dash", async (HttpContext context) =>
        {
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/unauthorized");
                return;
            }
            var user = new User();
            List<Paste> pastes = new List<Paste>();
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                string uuid = string.Empty;

                var findUUIDCommand = connection.CreateCommand();
                findUUIDCommand.CommandText = "SELECT UUID FROM logins WHERE Token = @Token";
                findUUIDCommand.Parameters.AddWithValue("@Token", context.Request.Cookies["token"]);
                var findUUIDreader = await findUUIDCommand.ExecuteReaderAsync();
                await findUUIDreader.ReadAsync();
                uuid = findUUIDreader.GetString(0);

                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
                command.Parameters.AddWithValue("@UUID", uuid);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                user.UID = reader.GetString(0);
                user.UUID = reader.GetString(1);
                user.Username = reader.GetString(2);
                user.PasswordHash = reader.GetString(3);
                user.CreationDate = reader.GetString(4);
                user.LastLoginDate = reader.GetString(5);
                user.Type = reader.GetInt32(6);

                var pastesCommand = connection.CreateCommand();
                pastesCommand.CommandText = "SELECT * FROM pastes WHERE Uploader = @Uploader ORDER BY UID DESC";
                pastesCommand.Parameters.AddWithValue("@Uploader", user.UUID);
                var pastesReader = await pastesCommand.ExecuteReaderAsync();
                while (await pastesReader.ReadAsync())
                {
                    var paste = new Paste
                    {
                        Title = pastesReader.GetString(1),
                        UnixDate = long.Parse(pastesReader.GetString(2)),
                        Size = pastesReader.GetString(3),
                        Visibility = pastesReader.GetString(4),
                        Id = pastesReader.GetString(5),
                    };
                    pastes.Add(paste);
                }

            }
            string pasteList = string.Empty;
            long totalSize = 0;

            if (pastes.Count == 0)
            {
                pasteList = "<h2>No pastes found</h1>";
            }
            else if (pastes.Count > 0)
            {
                foreach (var paste in pastes)
                {
                    totalSize += long.Parse(paste.Size);
                    var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                    string title = paste.Title;
                    if (title.Length > 20)
                    {
                        title = title.Substring(0, 20) + "...";
                    }
                    pasteList += $"<a class=\"list-a\" href=\"/{paste.Id}\"><li class=\"list-item \">{paste.Title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                }
            }
            string totalSizeString = ConvertToBytes(totalSize.ToString());

            var html = File.ReadAllText("assets/dash.html");
            if (user.Type == 255)
            {
                html = File.ReadAllText("assets/admin.html");
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var usersCommand = connection.CreateCommand();
                    usersCommand.CommandText = "SELECT * FROM users LIMIT 10";
                    var usersReader = await usersCommand.ExecuteReaderAsync();
                    List<User> users = new List<User>();
                    while (await usersReader.ReadAsync())
                    {
                        var userLocal = new User
                        {
                            UID = usersReader.GetString(0),
                            UUID = usersReader.GetString(1),
                            Username = usersReader.GetString(2),
                            PasswordHash = usersReader.GetString(3),
                            CreationDate = usersReader.GetString(4),
                            LastLoginDate = usersReader.GetString(5),
                            Type = usersReader.GetInt32(6),
                        };
                        users.Add(userLocal);
                    }
                    string userList = string.Empty;
                    foreach (var userLocal in users)
                    {
                        userList += $"<a class=\"list-a\" href=\"/admin/u/{userLocal.Username}\"><li class=\"list-item \">{userLocal.Username}</li></a>";
                    }
                    html = html.Replace("{accounts}", userList);
                }
            }
            html = html.Replace("{html}", "<a href=\"/logout\">logout</a>");
            html = html.Replace("{username}", user.Username);
            html = html.Replace("{uuid}", user.UUID);
            html = html.Replace("{uid}", user.UID);
            html = html.Replace("{creationdate}", user.CreationDate);
            html = html.Replace("{lastlogindate}", user.LastLoginDate);
            html = html.Replace("{type}", accountType[user.Type]);
            html = html.Replace("{totalpastes}", pastes.Count.ToString());
            html = html.Replace("{totalsize}", totalSizeString);
            html = html.Replace("{pastes}", pasteList);
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;
        });
        app.MapGet("/logout", async (HttpContext context) =>
        {
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/");
                return;
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM logins WHERE Token = @Token";
                command.Parameters.AddWithValue("@Token", context.Request.Cookies["token"]);
                await command.ExecuteNonQueryAsync();
            }
            context.Response.Cookies.Delete("token");
            context.Response.Redirect("/");
            return;
        });
        app.MapGet("/paste-not-found", async (HttpContext context) =>
        {
            context.Response.StatusCode = 404;
            var error_html = File.ReadAllText("assets/error.html");
            error_html = error_html.Replace("{code}", "404");
            error_html = error_html.Replace("{message}", "Paste not found");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                error_html = error_html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                error_html = error_html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
            }
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(error_html);
            return;
        });
        app.MapGet("/unauthorized", async (HttpContext context) =>
        {
            context.Response.StatusCode = 404;
            var error_html = File.ReadAllText("assets/error.html");
            error_html = error_html.Replace("{code}", "401");
            error_html = error_html.Replace("{message}", "Unauthorized");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                error_html = error_html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                error_html = error_html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
            }
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(error_html);
            return;
        });
        app.MapGet("/banned", async (HttpContext context) =>
        {
            context.Response.StatusCode = 404;
            var error_html = File.ReadAllText("assets/banned.html");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            var user = new User();
            if (loggedIn)
            {
                user = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                if (user.State != 1 && user.State != 2)
                {
                    context.Response.Redirect("/");
                    return;
                }
                error_html = error_html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                context.Response.Redirect("/");
                return;
            }
            var punishment = await GetPunishmentAsync(user.UUID);
            var unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();
            if (punishment.ExpirationDate < unixNow)
            {
                await UnbanUUIDAsync(user.UUID);
                context.Response.Redirect("/");
                return;
            }
            error_html = error_html.Replace("{code}", "403");
            error_html = error_html.Replace("{message}", $"You are banned until <a id=\"unix-date\">{punishment.ExpirationDate}</a> for \"{punishment.Reason}\"");
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(error_html);
            return;
        });
        app.MapGet("/{id}", async (HttpContext context) =>
        {
            var id = context.Request?.RouteValues?["id"]?.ToString();
            var token = context.Request.Cookies["token"];

            if (!File.Exists($"pastes/{id}.txt"))
            {
                context.Response.StatusCode = 404;
                context.Response.Redirect("/paste-not-found");
                return;
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", id);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.Redirect("/paste-not-found");
                    return;
                }
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    UnixDate = long.Parse(reader.GetString(2)),
                    Size = reader.GetString(3),
                    Visibility = reader.GetString(4),
                    Id = id,
                    Uploader = reader.GetString(6),
                };
                var loggedInUser = new User();

                if (await IsLoggedInAsync(token))
                {
                    loggedInUser = await GetLoggedInUserAsync(token);
                }

                var userCommand = connection.CreateCommand();
                userCommand.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
                userCommand.Parameters.AddWithValue("@UUID", paste.Uploader ?? "88ef478d-8831-4aea-be0d-9c449505072a");
                var userReader = await userCommand.ExecuteReaderAsync();
                await userReader.ReadAsync();

                string title = paste.Title;

                var user = new User();
                if (userReader.HasRows)
                {
                    user.UID = userReader.GetString(0);
                    user.UUID = userReader.GetString(1);
                    user.Username = userReader.GetString(2);
                    user.CreationDate = userReader.GetString(4);
                    user.LastLoginDate = userReader.GetString(5);
                    user.Type = userReader.GetInt32(6);
                }

                var html = File.ReadAllText("assets/paste.html");
                if (paste.Visibility == "Private")
                {
                    html = File.ReadAllText("assets/privatepaste.html");
                    html = html.Replace("{password}", "");
                }
                html = html.Replace("{pasteid}", paste.Id);

                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
                return;
            }
        });
        app.MapGet("/raw/{id}", async (HttpContext context) =>
        {
            var id = context.Request?.RouteValues?["id"]?.ToString();
            var filePath = $"pastes/{id}.txt";

            if (!File.Exists(filePath))
            {
                context.Response.StatusCode = 404;
                var json = new JObject
                {
                    ["error"] = "Paste not found"
                };
                return;
            }
            if (id.Length == 24)
            {
                var password = context.Request?.Query["password"].ToString();
                if (string.IsNullOrEmpty(password))
                {
                    context.Response.StatusCode = 401;
                    var json = new JObject
                    {
                        ["error"] = "Password required"
                    };
                    return;
                }
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                    command.Parameters.AddWithValue("@ID", id);
                    var reader = await command.ExecuteReaderAsync();
                    await reader.ReadAsync();
                    if (!reader.HasRows)
                    {
                        context.Response.StatusCode = 404;
                        var json = new JObject
                        {
                            ["error"] = "Paste not found"
                        };
                        return;
                    }
                    var paste = new PrivatePaste
                    {
                        Title = reader.GetString(1),
                        UnixDate = long.Parse(reader.GetString(2)),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = id,
                        Uploader = reader.GetString(6),
                        PasswordHash = reader.GetString(7),
                    };
                    var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
                    if (BCrypt.Net.BCrypt.Verify(password,paste.PasswordHash) && paste.Visibility != "Private")
                    {
                        context.Response.StatusCode = 401;
                        var json = new JObject
                        {
                            ["error"] = "Invalid password"
                        };
                        return;
                    }
                    try
                    {
                        string decompressedEncryptedContent = await Compression.DecompressByteArrayToString(await File.ReadAllBytesAsync(filePath));
                        string text = Encryption.DecryptString(decompressedEncryptedContent, password);
                        context.Response.ContentType = "text/plain";
                        await context.Response.WriteAsync(text);
                    }
                    catch (Exception e)
                    {
                        await Logging.LogError(e.Message);
                        context.Response.StatusCode = 401;
                        var json = new JObject
                        {
                            ["error"] = "Invalid password or Failed to decompress text"
                        };
                        return;
                    }
                    return;
                }
            }

            var fileInfo = new FileInfo(filePath);
            var fileSize = fileInfo.Length;

            context.Response.ContentType = "text/plain";
            context.Response.ContentLength = fileSize;
            var _content = await File.ReadAllBytesAsync(filePath);
            if (Compression.IsCompressed(_content))
            {
                _content = await Compression.DecompressByteArray(_content);
            }
            using (var stream = new MemoryStream(_content))
            {
                await stream.CopyToAsync(context.Response.Body);
            }
        });

        app.MapGet("/pastes", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets/recent_pastes.html");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes ORDER BY UID DESC LIMIT 10";
                var reader = await command.ExecuteReaderAsync();
                string pastes = string.Empty;

                while (await reader.ReadAsync())
                {
                    var paste = new Paste
                    {
                        Title = reader.GetString(1),
                        UnixDate = long.Parse(reader.GetString(2)),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = reader.GetString(5),
                    };
                    string title = paste.Title;
                    if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                    {
                        continue;
                    }
                    if (paste.Title == "" || string.IsNullOrEmpty(paste.Title))
                    {
                        title = $"Untitled {reader.GetString(0)}";
                    }
                    if (paste.Title.Length > 40)
                    {
                        title = paste.Title.Substring(0, 40) + "...";
                    }
                    var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));

                    pastes += $"<a title=\"{paste.Title}\" href=\"/{paste.Id}\"><li>{title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                }
                if (string.IsNullOrEmpty(pastes))
                {
                    pastes = "<h2>No pastes found</h1>";
                }
                html = html.Replace("{pastes}", pastes);
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
                return;
            }
        }).RequireRateLimiting("fixed-bigger");
        app.MapGet("/archive", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets/archives.html");
            var page = context.Request?.Query["page"].ToString();
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;

        }).RequireRateLimiting("fixed-bigger");
        app.MapGet("/u/{username}", async (HttpContext context) =>
        {
            string username = context.Request?.RouteValues?["username"]?.ToString();
            var html = File.ReadAllText(@"assets/user.html");
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE Username LIKE @Username";
                command.Parameters.AddWithValue("@Username", username);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    html = File.ReadAllText(@"assets/error.html");
                    html = html.Replace("{code}", "404");
                    html = html.Replace("{message}", "User not found");
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                    return;
                }
                else
                {
                    var user = new User
                    {
                        UID = reader.GetString(0),
                        UUID = reader.GetString(1),
                        Username = reader.GetString(2),
                        PasswordHash = reader.GetString(3),
                        CreationDate = reader.GetString(4),
                        LastLoginDate = reader.GetString(5),
                        Type = reader.GetInt32(6),
                        State = reader.GetInt32(7),
                    };
                    List<Paste> pastes = new List<Paste>();
                    var pastesCommand = connection.CreateCommand();
                    pastesCommand.CommandText = "SELECT * FROM pastes WHERE Uploader LIKE @Uploader ORDER BY UID DESC";
                    pastesCommand.Parameters.AddWithValue("@Uploader", user.UUID);
                    var pastesReader = await pastesCommand.ExecuteReaderAsync();
                    while (await pastesReader.ReadAsync())
                    {
                        var paste = new Paste
                        {
                            Title = pastesReader.GetString(1),
                            UnixDate = long.Parse(pastesReader.GetString(2)),
                            Size = pastesReader.GetString(3),
                            Visibility = pastesReader.GetString(4),
                            Id = pastesReader.GetString(5),
                        };
                        if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                        {
                            continue;
                        }
                        pastes.Add(paste);
                    }
                    string pasteList = string.Empty;
                    long totalSize = 0;
                    foreach (var paste in pastes)
                    {
                        totalSize += long.Parse(paste.Size);
                        var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                        string title = paste.Title;
                        if (title.Length > 20)
                        {
                            title = title.Substring(0, 20) + "...";
                        }
                        pasteList += $"<a class=\"list-a\" href=\"/{paste.Id}\"><li class=\"list-item \">{paste.Title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                    }
                    html = html.Replace("{username}", user.Username);
                    html = html.Replace("{uid}", user.UID);
                    html = html.Replace("{creationdate}", user.CreationDate);
                    html = html.Replace("{type}", accountType[user.Type]);
                    html = html.Replace("{totalpastes}", pastes.Count.ToString());
                    html = html.Replace("{totalsize}", ConvertToBytes(totalSize.ToString()));
                    html = html.Replace("{pastes}", pasteList);
                    if (await IsLoggedInAsync(context.Request.Cookies["token"]))
                    {
                        var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                        if (loggedInUser.UUID == user.UUID)
                        {
                            html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                        }
                        else
                        {
                            html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                        }
                    }
                    else
                    {
                        html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
                    }
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                    return;
                }
            }
        }).RequireRateLimiting("fixed-xl");
        app.MapGet("/uid/{uid}", async (HttpContext context) =>
        {
            string username = context.Request?.RouteValues?["uid"]?.ToString();
            var html = File.ReadAllText(@"assets/user.html");
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE UID = @Username";
                command.Parameters.AddWithValue("@Username", username);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    html = File.ReadAllText(@"assets/error.html");
                    html = html.Replace("{code}", "404");
                    html = html.Replace("{message}", "User not found");
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                    return;
                }
                else
                {
                    var user = new User
                    {
                        UID = reader.GetString(0),
                        UUID = reader.GetString(1),
                        Username = reader.GetString(2),
                        PasswordHash = reader.GetString(3),
                        CreationDate = reader.GetString(4),
                        LastLoginDate = reader.GetString(5),
                        Type = reader.GetInt32(6),
                        State = reader.GetInt32(7),
                    };
                    List<Paste> pastes = new List<Paste>();
                    var pastesCommand = connection.CreateCommand();
                    pastesCommand.CommandText = "SELECT * FROM pastes WHERE Uploader LIKE @Uploader ORDER BY UID DESC";
                    pastesCommand.Parameters.AddWithValue("@Uploader", user.UUID);
                    var pastesReader = await pastesCommand.ExecuteReaderAsync();
                    while (await pastesReader.ReadAsync())
                    {
                        var paste = new Paste
                        {
                            Title = pastesReader.GetString(1),
                            UnixDate = long.Parse(pastesReader.GetString(2)),
                            Size = pastesReader.GetString(3),
                            Visibility = pastesReader.GetString(4),
                            Id = pastesReader.GetString(5),
                        };
                        if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                        {
                            continue;
                        }
                        pastes.Add(paste);
                    }
                    string pasteList = string.Empty;
                    long totalSize = 0;
                    foreach (var paste in pastes)
                    {
                        totalSize += long.Parse(paste.Size);
                        var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                        string title = paste.Title;
                        if (title.Length > 20)
                        {
                            title = title.Substring(0, 20) + "...";
                        }
                        pasteList += $"<a class=\"list-a\" href=\"/{paste.Id}\"><li class=\"list-item \">{paste.Title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                    }
                    html = html.Replace("{username}", user.Username);
                    html = html.Replace("{uid}", user.UID);
                    html = html.Replace("{creationdate}", user.CreationDate);
                    html = html.Replace("{type}", accountType[user.Type]);
                    html = html.Replace("{totalpastes}", pastes.Count.ToString());
                    html = html.Replace("{totalsize}", ConvertToBytes(totalSize.ToString()));
                    html = html.Replace("{pastes}", pasteList);
                    if (await IsLoggedInAsync(context.Request.Cookies["token"]))
                    {
                        var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                        if (loggedInUser.UUID == user.UUID)
                        {
                            html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                        }
                        else
                        {
                            html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                        }
                    }
                    else
                    {
                        html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
                    }
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                    return;
                }
            }
        }).RequireRateLimiting("fixed-xl");

        #region ADMIN PANEL

        app.MapGet("/admin/u/{user}", async (HttpContext context) => {
            string user = context.Request?.RouteValues?["user"]?.ToString();
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/unauthorized");
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                if (loggedInUser.Type != 255)
                {
                    context.Response.Redirect("/unauthorized");
                    return;
                }
            }

            var html = File.ReadAllText(@"assets/admin/user.html");
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE Username LIKE @Username";
                command.Parameters.AddWithValue("@Username", user);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    html = File.ReadAllText(@"assets/error.html");
                    html = html.Replace("{code}", "404");
                    html = html.Replace("{message}", "User not found");
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                    return;
                }
                else
                {
                    var userLocal = new User
                    {
                        UID = reader.GetString(0),
                        UUID = reader.GetString(1),
                        Username = reader.GetString(2),
                        PasswordHash = reader.GetString(3),
                        CreationDate = reader.GetString(4),
                        LastLoginDate = reader.GetString(5),
                        Type = reader.GetInt32(6),
                        State = reader.GetInt32(7),
                    };
                    List<Paste> pastes = new List<Paste>();
                    var pastesCommand = connection.CreateCommand();
                    pastesCommand.CommandText = "SELECT * FROM pastes WHERE Uploader = @Uploader ORDER BY UID DESC";
                    pastesCommand.Parameters.AddWithValue("@Uploader", userLocal.UUID);
                    var pastesReader = await pastesCommand.ExecuteReaderAsync();
                    while (await pastesReader.ReadAsync())
                    {
                        var paste = new Paste
                        {
                            Title = pastesReader.GetString(1),
                            UnixDate = long.Parse(pastesReader.GetString(2)),
                            Size = pastesReader.GetString(3),
                            Visibility = pastesReader.GetString(4),
                            Id = pastesReader.GetString(5),
                        };
                        pastes.Add(paste);
                    }
                    string pasteList = string.Empty;
                    long totalSize = 0;
                    foreach (var paste in pastes)
                    {
                        totalSize += long.Parse(paste.Size);
                        var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                        string title = paste.Title;
                        if (title.Length > 20)
                        {
                            title = title.Substring(0, 20) + "...";
                        }
                        pasteList += $"<a class=\"list-a\" href=\"/{paste.Id}\"><li class=\"list-item \">{paste.Title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                    }
                    html = html.Replace("{username}", userLocal.Username);
                    html = html.Replace("{uuid}", userLocal.UUID);
                    html = html.Replace("{uid}", userLocal.UID);
                    html = html.Replace("{creationdate}", userLocal.CreationDate);
                    html = html.Replace("{lastlogindate}", userLocal.LastLoginDate);
                    html = html.Replace("{type}", accountType[userLocal.Type]);
                    html = html.Replace("{totalpastes}", pastes.Count.ToString());
                    html = html.Replace("{totalsize}", ConvertToBytes(totalSize.ToString()));
                    html = html.Replace("{pastes}", pasteList);
                    html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                    string typeban = string.Empty;
                    if (userLocal.State == 0)
                    {
                        typeban = "ban";
                    }
                    else if (userLocal.State == 1)
                    {
                        typeban = "unban";
                    }
                    html = html.Replace("{typeban}", typeban);
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(html);
                }
                return;
            }
        });

        app.MapPost("/api/accounts/admin/ban", async (HttpContext context) =>
        {
            var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                
                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var uuid = SanitizeInput(data["uuid"]?.ToString() ?? "");
            var reason = SanitizeInput(data["reason"]?.ToString() ?? "No reason provided");
            var expiration = SanitizeInput(data["expiration"]?.ToString() ?? "64060635661");
            try { DateTimeOffset.FromUnixTimeSeconds(long.Parse(expiration)); } catch { expiration = "64060635661"; }
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrWhiteSpace(uuid))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var user = new User();
            using (var connection = new SqliteConnection("Data Source = pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
                command.Parameters.AddWithValue("@UUID", uuid);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "User not found" }.ToString());
                    return;
                }
                user = new User
                {
                    UID = reader.GetString(0),
                    UUID = reader.GetString(1),
                    Username = reader.GetString(2),
                    PasswordHash = reader.GetString(3),
                    CreationDate = reader.GetString(4),
                    LastLoginDate = reader.GetString(5),
                    Type = reader.GetInt32(6),
                    State = reader.GetInt32(7),
                };
                if (user.State == 1)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "User is already banned" }.ToString());
                    return;
                }
                if (user.Type == 255)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Cannot ban an admin" }.ToString());
                    return;
                }
                var banUserCommand = connection.CreateCommand();
                banUserCommand.CommandText = "UPDATE users SET State = 1 WHERE UUID = @UUID";
                banUserCommand.Parameters.AddWithValue("@UUID", uuid);
                await banUserCommand.ExecuteNonQueryAsync();

                var punishedUsersCommand = connection.CreateCommand();
                punishedUsersCommand.CommandText = "INSERT INTO punishedUsers (UUID,State, Reason,ExpirationDate, Punisher) VALUES (@UUID, @State, @Reason,@ExpirationDate, @Punisher)";
                punishedUsersCommand.Parameters.AddWithValue("@UUID", uuid);
                punishedUsersCommand.Parameters.AddWithValue("@State", 1);
                punishedUsersCommand.Parameters.AddWithValue("@Reason", reason);
                punishedUsersCommand.Parameters.AddWithValue("@ExpirationDate", expiration);
                punishedUsersCommand.Parameters.AddWithValue("@Punisher", loggedInUser.UUID);
                await punishedUsersCommand.ExecuteNonQueryAsync();
            }
            await Logging.LogInfo($"Account {user.Username}({user.UUID}) has been banned by {loggedInUser.Username}({loggedInUser.UUID}) for {reason}");
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(new JObject { ["message"] = "User banned" }.ToString());
            return;
        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/admin/unban", async (HttpContext context) =>
        {
            var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {

                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var uuid = SanitizeInput(data["uuid"]?.ToString() ?? "");
            var reason = SanitizeInput(data["reason"]?.ToString() ?? "No reason provided");
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrWhiteSpace(uuid))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var user = await UnbanUUIDAsync(uuid);
            await Logging.LogInfo($"Account {user.Username}({user.UUID}) has been unbanned by {loggedInUser.Username}({loggedInUser.UUID}) for {reason}");
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(new JObject { ["message"] = "User unbanned" }.ToString());
        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/admin/change-password", async (HttpContext context) =>
        {
            var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {

                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var uuid = SanitizeInput(data["uuid"]?.ToString() ?? "");
            var newPassword = SanitizeInput(data["password"]?.ToString() ?? GenerateRandomPassword(50));
            if (string.IsNullOrEmpty(newPassword) || string.IsNullOrWhiteSpace(newPassword))
            {
                newPassword = GenerateRandomPassword(50);
            }
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrWhiteSpace(uuid))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var user = new User();
            using (var connection = new SqliteConnection("Data Source = pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
                command.Parameters.AddWithValue("@UUID", uuid);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "User not found" }.ToString());
                    return;
                }
                user = new User
                {
                    UID = reader.GetString(0),
                    UUID = reader.GetString(1),
                    Username = reader.GetString(2),
                    PasswordHash = reader.GetString(3),
                    CreationDate = reader.GetString(4),
                    LastLoginDate = reader.GetString(5),
                    Type = reader.GetInt32(6),
                    State = reader.GetInt32(7),
                };
                var changePasswordCommand = connection.CreateCommand();
                changePasswordCommand.CommandText = "UPDATE users SET PasswordHash = @Password WHERE UUID = @UUID";
                changePasswordCommand.Parameters.AddWithValue("@Password", BCrypt.Net.BCrypt.HashPassword(newPassword));
                changePasswordCommand.Parameters.AddWithValue("@UUID", uuid);
                await changePasswordCommand.ExecuteNonQueryAsync();
                var deleteLoginsCommand = connection.CreateCommand();
                deleteLoginsCommand.CommandText = "DELETE FROM logins WHERE UUID = @UUID";
                deleteLoginsCommand.Parameters.AddWithValue("@UUID", uuid);
                await deleteLoginsCommand.ExecuteNonQueryAsync();
            }
            await Logging.LogInfo($"Account {user.Username}({user.UUID}) has had their password changed by {loggedInUser.Username}({loggedInUser.UUID})");
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(new JObject { ["message"] = "Password changed", ["password"] = newPassword }.ToString());
        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/admin/get", async (HttpContext context) =>
        {
            var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
            var htmlQuery = context.Request.Query["html"].ToString();
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {

                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            List<User> users = new List<User>();
            JArray usersJson = new JArray();
            string html = string.Empty;
            long offset = data["offset"]?.ToObject<long>() ?? 0;
            string searhc = data["search"]?.ToString() ?? "";
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users ORDER BY UID LIMIT 10 OFFSET @Offset";
                command.Parameters.AddWithValue("@Offset", offset);
                var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var user = new User
                    {
                        UID = reader.GetString(0),
                        UUID = reader.GetString(1),
                        Username = reader.GetString(2),
                        PasswordHash = reader.GetString(3),
                        CreationDate = reader.GetString(4),
                        LastLoginDate = reader.GetString(5),
                        Type = reader.GetInt32(6),
                        State = reader.GetInt32(7),
                    };
                    users.Add(user);
                    if (htmlQuery.ToLower() == "true")
                    {
                        html += $"<a class=\"list-a\" href=\"/admin/u/{user.Username}\"><li class=\"list-item \">{user.Username}</li></a>";
                    }
                    else
                    {
                        JObject userJson = new JObject();
                        userJson["uid"] = user.UID;
                        userJson["uuid"] = user.UUID;
                        userJson["username"] = user.Username;
                        userJson["creationdate"] = user.CreationDate;
                        userJson["lastlogindate"] = user.LastLoginDate;
                        userJson["type"] = accountType[user.Type];
                        userJson["state"] = user.State;
                        usersJson.Add(userJson);
                    
                    }
                }
            }
            if (htmlQuery.ToLower() == "true")
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
            }
            else
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(usersJson.ToString());
            }
        }).RequireRateLimiting("fixed-bigger");
        app.MapPost("/api/accounts/admin/search", async (HttpContext context) =>
        {
            var loggedInUser = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
            var htmlQuery = context.Request.Query["html"].ToString();
            if (!await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {

                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            List<User> users = new List<User>();
            JArray usersJson = new JArray();
            string html = string.Empty;
            string search = data["search"]?.ToString() ?? "";
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE Username LIKE @Search ORDER BY UID";
                command.Parameters.AddWithValue("@Search", $"%{search}%");
                var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    var user = new User
                    {
                        UID = reader.GetString(0),
                        UUID = reader.GetString(1),
                        Username = reader.GetString(2),
                        PasswordHash = reader.GetString(3),
                        CreationDate = reader.GetString(4),
                        LastLoginDate = reader.GetString(5),
                        Type = reader.GetInt32(6),
                        State = reader.GetInt32(7),
                    };
                    users.Add(user);
                    if (htmlQuery.ToLower() == "true")
                    {
                        html += $"<a class=\"list-a\" href=\"/admin/u/{user.Username}\"><li class=\"list-item \">{user.Username}</li></a>";
                    }
                    else
                    {
                        JObject userJson = new JObject();
                        userJson["uid"] = user.UID;
                        userJson["uuid"] = user.UUID;
                        userJson["username"] = user.Username;
                        userJson["creationdate"] = user.CreationDate;
                        userJson["lastlogindate"] = user.LastLoginDate;
                        userJson["type"] = accountType[user.Type];
                        userJson["state"] = user.State;
                        usersJson.Add(userJson);

                    }
                }
            }
            if (htmlQuery.ToLower() == "true")
            {
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
            }
            else
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(usersJson.ToString());
            }
        }).RequireRateLimiting("fixed-bigger");
        app.MapPost("/api/pastes/admin/change-id", async (HttpContext context) =>
        {
            var token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            var user = await GetLoggedInUserAsync(token);
            if (string.IsNullOrEmpty(user.UID) || user.Type != 255)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var json = JObject.Parse(requestBody);
            var pasteId = SanitizeInput(json["pasteId"]?.ToString() ?? "");
            var newPasteId = SanitizeInput(json["newPasteId"]?.ToString() ?? "");

            if (string.IsNullOrEmpty(pasteId) || string.IsNullOrWhiteSpace(pasteId) || string.IsNullOrEmpty(newPasteId) || string.IsNullOrWhiteSpace(newPasteId))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            if (!File.Exists($"pastes/{pasteId}.txt"))
            {
                context.Response.StatusCode = 404;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                return;
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE Id = @Id";
                command.Parameters.AddWithValue("@Id", pasteId);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                    return;
                }
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    UnixDate = long.Parse(reader.GetString(2)),
                    Size = reader.GetString(3),
                    Visibility = reader.GetString(4),
                    Id = reader.GetString(5),
                    Uploader = reader.GetString(6),
                };
                var changeIdCommand = connection.CreateCommand();
                changeIdCommand.CommandText = "UPDATE pastes SET Id = @NewId WHERE Id = @Id";
                changeIdCommand.Parameters.AddWithValue("@NewId", newPasteId);
                changeIdCommand.Parameters.AddWithValue("@Id", pasteId);
                await changeIdCommand.ExecuteNonQueryAsync();
                File.Move($"pastes/{pasteId}.txt", $"pastes/{newPasteId}.txt");
                if (File.Exists($"pastes/{pasteId}.txt"))
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Failed to change paste ID" }.ToString());
                    return;
                }
                await Logging.LogInfo($"Paste {pasteId} has been changed to {newPasteId} by {user.Username}({user.UUID})");
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["message"] = "Paste ID changed" }.ToString());
            }
        }).RequireRateLimiting("fixed");

        #endregion

        #endregion

        #region API

        app.MapPost("/api/pastes/create", async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            string ip = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();
            string uploaderUUID = string.Empty;
            string token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            var user = await GetLoggedInUserAsync(token);

            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No content uploaded" }.ToString());
                return;
            }
            if (!string.IsNullOrEmpty(user.UUID))
            {
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT * FROM logins WHERE Token = @Token";
                    command.Parameters.AddWithValue("@Token", token);
                    var reader = await command.ExecuteReaderAsync();
                    await reader.ReadAsync();
                    uploaderUUID = reader.GetString(0);
                    
                    if (user.State != 0)
                    {
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(new JObject { ["error"] = "User is banned" }.ToString());
                        return;
                    }
                }
            }
            else
            {
                uploaderUUID = $"Anonymous-{Guid.NewGuid().ToString()}";
            }
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var title = SanitizeInput(data["title"]?.ToString() ?? "Untitled");
            var content = SanitizeInput(data["content"]?.ToString() ?? "");
            var visibility = SanitizeInput(data["visibility"]?.ToString() ?? "Public");

            if (content.Length > 500_000 || title.Length > 500)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Content or Title is too long" }.ToString());
                return;
            }
            if (visibility != "Public" && visibility != "Unlisted" && visibility != "Private")
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid visibility" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(content) || string.IsNullOrWhiteSpace(content))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var paste = new Paste();
            if (visibility == "Private")
            {
                var password = SanitizeInput(data["password"]?.ToString() ?? GenerateRandomPassword(30));
                var privatePaste = await CreatePrivatePaste(title, content, password, uploaderUUID);
                if (privatePaste == null)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Failed to create paste" }.ToString());
                    return;
                }
                if (!File.Exists($"pastes/{privatePaste.Id}.txt"))
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Failed to create paste" }.ToString());
                    return;
                }
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                string _time = DateTimeOffset.FromUnixTimeSeconds(privatePaste.UnixDate ?? 0).ToString().Split("+")[0].TrimEnd();
                JObject _responseJson = new JObject();
                _responseJson["pasteId"] = privatePaste.Id;
                _responseJson["pasteSize"] = ConvertToBytes(privatePaste.Size ?? string.Empty);
                _responseJson["pasteDate"] = _time;
                _responseJson["pasteVisibility"] = privatePaste.Visibility;

                Log _log = await Logging.LogRequestAsync(context);
                await Logging.LogInfo($"Private Paste created, {ConvertToBytes(privatePaste.Size ?? string.Empty)}, {privatePaste.Id} by {uploaderUUID}");
                await context.Response.WriteAsync(_responseJson.ToString());
                return;
            }
            else
            {
                var pasteData = new Paste
                {
                    Content = content,
                    Title = title,
                    Visibility = visibility,
                    Uploader = uploaderUUID
                };
                paste = await CreatePaste(pasteData);
            }
            

            if (!File.Exists($"pastes/{paste?.Id}.txt") || paste == null)
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Failed to create paste" }.ToString());
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";

            string time = DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0).ToString().Split("+")[0].TrimEnd();

            JObject responseJson = new JObject();
            responseJson["pasteId"] = paste.Id;
            responseJson["pasteSize"] = ConvertToBytes(paste.Size ?? string.Empty);
            responseJson["pasteDate"] = time;
            responseJson["pasteVisibility"] = paste.Visibility;

            Log log = await Logging.LogRequestAsync(context);

            await Logging.LogInfo($"Paste created, {ConvertToBytes(paste.Size ?? string.Empty)}, {paste.Id} by {uploaderUUID}");

            await context.Response.WriteAsync(responseJson.ToString());
            return;

        }).RequireRateLimiting("fixed");
        app.MapPost("/api/pastes/edit", async (HttpContext context) =>
        {
            var token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            var user = await GetLoggedInUserAsync(token);
            if (user.UUID == null || user.UID == null)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            if (user.State != 0)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "User is banned/suspended" }.ToString());
                return;
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var id = SanitizeInput(data["id"]?.ToString() ?? "");
            var content = SanitizeInput(data["text"]?.ToString() ?? "");

            if (string.IsNullOrEmpty(id) || string.IsNullOrWhiteSpace(id) || string.IsNullOrEmpty(content) || string.IsNullOrWhiteSpace(content))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", id);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                    return;
                }
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    UnixDate = long.Parse(reader.GetString(2)),
                    Size = reader.GetString(3),
                    Visibility = reader.GetString(4),
                    Id = reader.GetString(5),
                };
                if (paste.Visibility == "Private")
                {
                    context.Response.StatusCode = 501;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Editing private pastes has not been implemented." }.ToString());
                    return;
                }

                var updateCommand = connection.CreateCommand();
                updateCommand.CommandText = "UPDATE pastes SET Size = @Size WHERE ID = @ID";
                updateCommand.Parameters.AddWithValue("@Size", content.Length.ToString());
                updateCommand.Parameters.AddWithValue("@ID", id);
                await updateCommand.ExecuteNonQueryAsync();

                var compressedContent = await Compression.CompressString(content);
                await File.WriteAllBytesAsync($"pastes/{id}.txt", compressedContent);
                await Logging.LogInfo($"Paste {paste.Id} edited by {user.Username}({user.UUID})");
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(new JObject { ["message"] = "Paste edited" }.ToString());
        }).RequireRateLimiting("fixed-bigger");
        app.MapPost("/api/pastes/delete", async (HttpContext context) =>
        {
            string token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            var log = await Logging.LogRequestAsync(context);
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (!await IsLoggedInAsync(token))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var id = SanitizeInput(data["id"]?.ToString() ?? "");
            if (string.IsNullOrEmpty(id) || string.IsNullOrWhiteSpace(id))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", id);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                    return;
                }
                string UUID = reader.GetString(6);
                var verifyOwnershipCommand = connection.CreateCommand();
                verifyOwnershipCommand.CommandText = "SELECT * FROM logins WHERE Token = @Token";
                verifyOwnershipCommand.Parameters.AddWithValue("@Token", token);
                var verifyReader = await verifyOwnershipCommand.ExecuteReaderAsync();
                await verifyReader.ReadAsync();
                var user = new User();
                if (verifyReader.HasRows)
                {
                    user = await GetLoggedInUserAsync(token);
                }

                if (user.Type != 255 && verifyReader.GetString(0) != UUID )
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }


                var deleteCommand = connection.CreateCommand();
                deleteCommand.CommandText = "DELETE FROM pastes WHERE ID = @ID";
                deleteCommand.Parameters.AddWithValue("@ID", id);
                await deleteCommand.ExecuteNonQueryAsync();
                File.Delete($"pastes/{id}.txt");
                await Logging.LogInfo($"Paste {id} deleted by {user.Username}({user.UUID})");
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync(new JObject { ["message"] = "Paste deleted" }.ToString());
            }

        }).RequireRateLimiting("fixed");
        app.MapPost("/api/pastes/search", async (HttpContext context) =>
        {
            var log = await Logging.LogRequestAsync(context);
            var parameters = context.Request.Query;
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var query = SanitizeInput(data["query"]?.ToString() ?? "");

            if (string.IsNullOrEmpty(query) || string.IsNullOrWhiteSpace(query))
            {
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var command = connection.CreateCommand();
                    command.CommandText = $"SELECT * FROM pastes WHERE Visibility != 'Private' ORDER BY UID DESC LIMIT 50";
                    var reader = await command.ExecuteReaderAsync();
                    string pastes = string.Empty;
                    JArray pastesArray = new JArray();
                    while (await reader.ReadAsync())
                    {
                        var paste = new Paste
                        {
                            Title = reader.GetString(1),
                            UnixDate = long.Parse(reader.GetString(2)),
                            Size = reader.GetString(3),
                            Visibility = reader.GetString(4),
                            Id = reader.GetString(5),
                        };
                        string title = paste.Title;
                        if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                        {
                            continue;
                        }
                        if (paste.Title == "" || string.IsNullOrEmpty(paste.Title))
                        {
                            title = $"Untitled {reader.GetString(0)}";
                        }
                        if (paste.Title.Length > 40)
                        {
                            title = paste.Title.Substring(0, 40) + "...";
                        }
                        var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                        if (string.IsNullOrEmpty(parameters["html"]))
                        {
                            JObject pasteJson = new JObject();
                            pasteJson["title"] = paste.Title;
                            pasteJson["id"] = paste.Id;
                            pasteJson["size"] = ConvertToBytes(paste.Size);
                            pasteJson["date"] = difference;
                            pasteJson["visibility"] = paste.Visibility;
                            pastesArray.Add(pasteJson);
                        }
                        else
                        {
                            pastes += $"<a title=\"{paste.Title}\" href=\"/{paste.Id}\"><li>{title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                        }
                    }
                    if (string.IsNullOrEmpty(pastes) && pastesArray.Count == 0)
                    {
                        pastes = "<h2>No pastes found</h2>";
                        pastesArray.Add(new JObject { ["error"] = "No pastes found" });
                        context.Response.StatusCode = 404;
                    }
                    else
                    {
                        context.Response.StatusCode = 200;
                    }
                    
                    if (string.IsNullOrEmpty(parameters["html"]))
                    {
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync(pastesArray.ToString());
                    }
                    else
                    {
                        context.Response.ContentType = "text/html";
                        await context.Response.WriteAsync(pastes);
                    }
                    return;
                }
            }

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE Title LIKE @Query";
                command.Parameters.AddWithValue("@Query", $"%{query}%");
                var reader = await command.ExecuteReaderAsync();
                JArray pastes = new JArray();
                string pastesHTML = string.Empty;
                while (await reader.ReadAsync())
                {
                    var paste = new Paste
                    {
                        Title = reader.GetString(1),
                        UnixDate = long.Parse(reader.GetString(2)),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = reader.GetString(5),
                    };
                    var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                    if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                    {
                        continue;
                    }
                    if (string.IsNullOrEmpty(parameters["html"]))
                    {
                        JObject pasteJson = new JObject();
                        pasteJson["title"] = paste.Title;
                        pasteJson["id"] = paste.Id;
                        pasteJson["size"] = ConvertToBytes(paste.Size);
                        pasteJson["date"] = difference;
                        pasteJson["visibility"] = paste.Visibility;
                        pastes.Add(pasteJson);
                    }
                    else
                    {
                        pastesHTML += $"<a title=\"{paste.Title}\" href=\"/{paste.Id}\"><li>{paste.Title} {difference}</li></a>";
                    }

                }
                context.Response.StatusCode = 200;
                if (string.IsNullOrEmpty(parameters["html"]))
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(pastes.ToString());
                }
                else
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(pastesHTML);
                }
            }

        }).RequireRateLimiting("fixed-bigger");
        app.MapPost("/api/pastes/get", async (HttpContext context) =>
        {
            var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (string.IsNullOrEmpty(body))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            try
            {
                JObject.Parse(body);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(body);
            var page = data["page"]?.ToObject<int>() ?? 1;

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                long pages = 1;
                var pagesCommand = connection.CreateCommand();
                pagesCommand.CommandText = "SELECT COUNT(*) FROM pastes WHERE Visibility != 'Private' AND Visibility != 'Untitled'";
                var pagesReader = await pagesCommand.ExecuteReaderAsync();
                await pagesReader.ReadAsync();
                if (pagesReader.HasRows)
                {
                    pages = (long)Math.Ceiling(pagesReader.GetInt32(0) / 50.0);
                }
                var command = connection.CreateCommand();
                if (page <= 1)
                {
                    command.CommandText = "SELECT * FROM pastes WHERE Visibility != 'Private' AND Visibility != 'Untitled' ORDER BY UID DESC LIMIT 50";
                }
                else
                {
                    command.CommandText = "SELECT * FROM pastes WHERE Visibility != 'Private' AND Visibility != 'Untitled' ORDER BY UID DESC LIMIT 50 OFFSET @Offset";
                    command.Parameters.AddWithValue("@Offset", (page - 1) * 50);
                }
                var reader = await command.ExecuteReaderAsync();
                JArray pastes = new JArray();
                while (await reader.ReadAsync())
                {
                    var paste = new Paste
                    {
                        Title = reader.GetString(1),
                        UnixDate = long.Parse(reader.GetString(2)),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = reader.GetString(5),
                    };
                    if (paste.Title == "")
                    {
                        paste.Title = $"Untitled {reader.GetString(0)}";
                    }
                    var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                    if (paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                    {
                        continue;
                    }
                    var _paste = new JObject();
                    _paste["title"] = paste.Title;
                    _paste["id"] = paste.Id;    
                    _paste["size"] = ConvertToBytes(paste.Size);
                    _paste["date"] = difference;
                    _paste["visibility"] = paste.Visibility;
                    pastes.Add(_paste);
                }
                await connection.CloseAsync();
                JObject resdata = new JObject();
                resdata["pages"] = pages;
                resdata["page"] = page;
                resdata["pastes"] = pastes;
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(resdata.ToString());
            }

        }).RequireRateLimiting("fixed-xl");
        app.MapGet("/api/pastes/info", async (HttpContext context) =>
        {
            var query = context.Request.Query;
            var id = query["id"].ToString();
            
            if (string.IsNullOrEmpty(id) || string.IsNullOrWhiteSpace(id))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request" }.ToString());
                return;
            }
            if (!File.Exists($"pastes/{id}.txt"))
            {
                context.Response.StatusCode = 404;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                return;
            }

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", id);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                    return;
                }
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    UnixDate = long.Parse(reader.GetString(2)),
                    Size = reader.GetString(3),
                    Visibility = reader.GetString(4),
                    Id = reader.GetString(5),
                    UID = long.Parse(reader.GetString(0)),
                    Uploader = reader.GetString(6)
                };
                var filelength = new FileInfo($"pastes/{id}.txt").Length;
                var user = await GetUserFromUUID(paste.Uploader);

                JObject responseJson = new JObject();
                responseJson["title"] = paste.Title;
                responseJson["id"] = paste.Id;
                responseJson["uid"] = paste.UID;
                responseJson["size"] = ConvertToBytes(paste.Size);
                responseJson["compressedSize"] = ConvertToBytes(filelength.ToString());
                responseJson["date"] = paste.UnixDate;
                responseJson["visibility"] = paste.Visibility;
                responseJson["uploader"] = user.Username;

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(responseJson.ToString());
            }
        });
        app.MapPost("/api/pastes/password/{pasteid}", async (HttpContext context) =>
        {
            var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (string.IsNullOrEmpty(body))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            try
            {
                JObject.Parse(body);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            var data = JObject.Parse(body);
            var password = SanitizeInput(data["password"]?.ToString() ?? "");
            var pasteId = context.Request.RouteValues["pasteid"].ToString();
            if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(password))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            if (!File.Exists($"pastes/{pasteId}.txt"))
            {
                context.Response.StatusCode = 404;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                return;
            }
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", pasteId);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Paste not found" }.ToString());
                    return;
                }
                var paste = new PrivatePaste
                {
                    Id = reader.GetString(5),
                    Title = reader.GetString(1),
                    Size = reader.GetString(3),
                    UnixDate = long.Parse(reader.GetString(2)),
                    Visibility = reader.GetString(4),
                    PasswordHash = reader.GetString(7),
                };
                var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
                if (!BCrypt.Net.BCrypt.Verify(password, paste.PasswordHash))
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Invalid password" }.ToString());
                    return;
                }
            }
            string decompressedEncryptedText = await Compression.DecompressByteArrayToString(File.ReadAllBytes($"pastes/{pasteId}.txt"));
            string decryptedText = Encryption.DecryptString(decompressedEncryptedText, password);

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(new JObject { ["content"] = decryptedText }.ToString());
        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/create", async (HttpContext context) =>
        {

            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            Log log = await Logging.LogRequestAsync(context);

            char[] disallowed = { ' ', '\'', '\"', '\\', '/', '(', ')', '[', ']', '{', '}', '<', '>', ';', ':', ',', '.', '!', '?', '@', '#', '$', '%', '^', '&', '*', '-', '+', '=', '~', '`' };

            if (IsLoggedInAsync(context.Request.Cookies["token"]).Result)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Already logged in" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            if (!requestBody.Contains("username") || !requestBody.Contains("password") || context.Request.ContentType != "application/json")
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var data = JObject.Parse(requestBody);
            var username = SanitizeInput(data["username"]?.ToString() ?? "");
            var password = SanitizeInput(data["password"]?.ToString() ?? "");
            var cfToken = SanitizeInput(data["cf"]?.ToString() ?? "");
            if (string.IsNullOrEmpty(cfToken) || string.IsNullOrEmpty(cfToken))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid Cloudflare Turnstile Token" }.ToString());
                return;
            }
            bool cfValid = await Turnstile.VerifyTurnstileToken(cfToken);
            if (!cfValid)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid Cloudflare Turnstile Token" }.ToString());
                return;
            }


            if (username.Length > 20 || username.Length < 3 || password.Length > 50 || password.Length < 8)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid username or password length" }.ToString());
                return;
            }
            if (username.IndexOfAny(disallowed) != -1)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid characters in username" }.ToString());
                return;
            }
            string token = string.Empty;
            string ip = string.Empty;
            string passwordHash = string.Empty;
            DateTime expirationDate = DateTime.Now.AddYears(1);

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE Username = @Username";
                command.Parameters.AddWithValue("@Username", username);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (reader.HasRows)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Username already exists" }.ToString());
                    return;
                }
                else if (!reader.HasRows && !reader.IsClosed)
                {
                    reader.Close();
                }
                var smallerSalt = BCrypt.Net.BCrypt.GenerateSalt(8);
                var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
                ip = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(log.IP, smallerSalt)));
                token = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString(), smallerSalt)));
                passwordHash = BCrypt.Net.BCrypt.HashPassword(password, salt);
                var insertCommand = connection.CreateCommand();
                insertCommand.CommandText = "INSERT INTO users (UUID, Username, PasswordHash, CreationDate, LastLoginDate, Type, State) VALUES (@UUID, @Username, @PasswordHash, @CreationDate, @LastLoginDate, @Type, @State)";
                insertCommand.Parameters.AddWithValue("@UUID", Guid.NewGuid().ToString());
                insertCommand.Parameters.AddWithValue("@Username", username);
                insertCommand.Parameters.AddWithValue("@PasswordHash", passwordHash);
                insertCommand.Parameters.AddWithValue("@CreationDate", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                insertCommand.Parameters.AddWithValue("@LastLoginDate", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                insertCommand.Parameters.AddWithValue("@Type", 0);
                insertCommand.Parameters.AddWithValue("@State", 0);
                await insertCommand.ExecuteNonQueryAsync();

                var loginCommand = connection.CreateCommand();
                loginCommand.CommandText = "INSERT INTO logins (UUID,UserAgent, IP, LoginTime,ExpireTime, Token) VALUES (@UUID,@UserAgent, @IP, @LoginTime,@ExpireTime, @Token)";
                loginCommand.Parameters.AddWithValue("@UserAgent", context.Request.Headers["User-Agent"].ToString());
                loginCommand.Parameters.AddWithValue("@UUID", insertCommand.Parameters["@UUID"].Value);
                loginCommand.Parameters.AddWithValue("@IP", ip);
                loginCommand.Parameters.AddWithValue("@LoginTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                loginCommand.Parameters.AddWithValue("@ExpireTime", ((DateTimeOffset)expirationDate).ToUnixTimeSeconds());
                loginCommand.Parameters.AddWithValue("@Token", token);
                await loginCommand.ExecuteNonQueryAsync();
            }
            var cookie = new CookieOptions
            {
                Expires = expirationDate,
                Secure = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict
            };

            context.Response.Cookies.Append("token", token, cookie);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await Logging.LogInfo($"Account {username} has been created");
            await context.Response.WriteAsync(new JObject { ["message"] = "Account created" }.ToString());


        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/login", (Delegate)(async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            try
            {
                JObject.Parse(requestBody);
            }
            catch
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid JSON" }.ToString());
                return;
            }
            Log log = await Logging.LogRequestAsync(context);

            if (IsLoggedInAsync(context.Request.Cookies["token"]).Result)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Already logged in" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            if (!requestBody.Contains("username") || !requestBody.Contains("password") || context.Request.ContentType != "application/json")
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var data = JObject.Parse(requestBody);
            var username = SanitizeInput(data["username"]?.ToString() ?? "");
            var password = SanitizeInput(data["password"]?.ToString() ?? "");
            var cfToken = SanitizeInput(data["cf"]?.ToString() ?? "");
            if (string.IsNullOrEmpty(cfToken) || string.IsNullOrEmpty(cfToken))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid Cloudflare Turnstile Token" }.ToString());
                return;
            }
            bool cfValid = await Turnstile.VerifyTurnstileToken(cfToken);
            if (!cfValid)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid Cloudflare Turnstile Token" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                return;
            }
            var smallerSalt = BCrypt.Net.BCrypt.GenerateSalt(8);
            var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
            string ip = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(log.IP, smallerSalt)));
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, salt);

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM users WHERE Username = @Username";
                command.Parameters.AddWithValue("@Username", username);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                if (!reader.HasRows)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                    return;
                }
                if (BCrypt.Net.BCrypt.Verify(password, reader.GetString(3)))
                {
                    string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString(), smallerSalt)));
                    DateTime expirationDate = DateTime.Now.AddYears(1);

                    var loginCommand = connection.CreateCommand();
                    loginCommand.CommandText = "INSERT INTO logins (UUID,UserAgent, IP, LoginTime,ExpireTime, Token) VALUES (@UUID,@UserAgent, @IP, @LoginTime,@ExpireTime, @Token)";
                    loginCommand.Parameters.AddWithValue("@UserAgent", log.UserAgent);
                    loginCommand.Parameters.AddWithValue("@UUID", reader.GetString(1));
                    loginCommand.Parameters.AddWithValue("@IP", ip);
                    loginCommand.Parameters.AddWithValue("@LoginTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    loginCommand.Parameters.AddWithValue("@ExpireTime", ((DateTimeOffset)expirationDate).ToUnixTimeSeconds());
                    loginCommand.Parameters.AddWithValue("@Token", token);
                    await loginCommand.ExecuteNonQueryAsync();

                    var userCommand = connection.CreateCommand();
                    userCommand.CommandText = "UPDATE users SET LastLoginDate = @LastLoginDate WHERE UUID = @UUID";
                    userCommand.Parameters.AddWithValue("@LastLoginDate", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    userCommand.Parameters.AddWithValue("@UUID", reader.GetString(1));
                    await userCommand.ExecuteNonQueryAsync();

                    var cookie = new CookieOptions
                    {
                        Expires = expirationDate,
                        Secure = true,
                        HttpOnly = true,
                        SameSite = SameSiteMode.Strict
                    };

                    context.Response.Cookies.Append("token", token, cookie);
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json";
                    await Logging.LogInfo($"Account {username} has logged in");
                    await context.Response.WriteAsync(new JObject { ["message"] = "Logged in" }.ToString());
                    return;
                }
                else
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                }
            }
        })).RequireRateLimiting("fixed");
        app.MapGet("/api/accounts/authenticate", (async (HttpContext context) =>
        {
            var token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }

            var user = await GetLoggedInUserAsync(token);
            if (user == null)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            if (user.UUID == null)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }

            var responseJson = new JObject();
            responseJson["message"] = "Authenticated";
            responseJson["username"] = user.Username;
            responseJson["uid"] = user.UID;
            responseJson["uuid"] = user.UUID;
            responseJson["type"] = accountType[user.Type];
            responseJson["state"] = accountState[user.State];
            responseJson["creationDate"] = DateTimeOffset.FromUnixTimeSeconds(long.Parse(user.CreationDate)).ToString().Split("+")[0].TrimEnd();
            responseJson["lastLoginDate"] = DateTimeOffset.FromUnixTimeSeconds(long.Parse(user.LastLoginDate)).ToString().Split("+")[0].TrimEnd();

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(responseJson.ToString());
        })).RequireRateLimiting("fixed-xl"); 

        #endregion

        await app.RunAsync();
    }

    public static async Task<Paste> CreatePaste(Paste paste)
    {
        paste.Id = GenerateRandomString(12);
        paste.UnixDate = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        paste.Size = paste.Content.Length.ToString();

        var compressedText = await Compression.CompressString(paste.Content);
        if (compressedText.LongLength < paste.Content.Length)
        {
            await File.WriteAllBytesAsync($"pastes/{paste.Id}.txt", compressedText);
        }
        else
        {
            await File.WriteAllTextAsync($"pastes/{paste.Id}.txt", paste.Content);
        }
        
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO pastes (Title, Date, Size, Visibility, ID, Uploader) VALUES (@Title, @Date, @Size, @Visibility, @ID, @Uploader)";
            command.Parameters.AddWithValue("@Title", paste.Title);
            command.Parameters.AddWithValue("@Date", paste.UnixDate);
            command.Parameters.AddWithValue("@Size", paste.Size);
            command.Parameters.AddWithValue("@Visibility", paste.Visibility);
            command.Parameters.AddWithValue("@ID", paste.Id);
            command.Parameters.AddWithValue("@Uploader", paste.Uploader);
            await command.ExecuteNonQueryAsync();
        }
        return paste;
    }
    public static async Task<PrivatePaste> CreatePrivatePaste(string title, string content, string password, string UUID)
    {
        var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
        string encryptedText = Encryption.EncryptString(content, password);
        var compressedEncryptedText = await Compression.CompressString(encryptedText);
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, salt);
        var paste = new PrivatePaste
        {
            Title = title,
            UnixDate = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Size = content.Length.ToString(),
            Id = GenerateRandomString(24),
            Uploader = UUID,
            PasswordHash = passwordHash
        };

        await File.WriteAllBytesAsync($"pastes/{paste.Id}.txt", compressedEncryptedText);
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO pastes (Title, Date, Size, Visibility, ID, Uploader, PasswordHash) VALUES (@Title, @Date, @Size, @Visibility, @ID, @Uploader, @PasswordHash)";
            command.Parameters.AddWithValue("@Title", paste.Title);
            command.Parameters.AddWithValue("@Date", paste.UnixDate);
            command.Parameters.AddWithValue("@Size", paste.Size);
            command.Parameters.AddWithValue("@Visibility", "Private");
            command.Parameters.AddWithValue("@ID", paste.Id);
            command.Parameters.AddWithValue("@Uploader", paste.Uploader);
            command.Parameters.AddWithValue("@PasswordHash", paste.PasswordHash);
            await command.ExecuteNonQueryAsync();
        }
        return paste;
    }
    public static string SanitizeInput(string input)
    {
        return input?.Replace("<", "&lt;").Replace(">", "&gt;") ?? string.Empty + input;
    }
    public static string ConvertToBytes(string length)
    {
        try
        {
            double.Parse(length);
        }
        catch
        {
            return "0 B";
        }
        string[] sizes = { "Bytes", "KB", "MB", "GB", "TB" };
        double len = double.Parse(length);
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }
        if (sizes[order] == "Bytes")
        {
            return $"{len:0.##} {sizes[order]}";
        }
        else
        {
            return $"{len:0.##}{sizes[order]}";
        }
    }
    public static string GetTimeDifference(DateTimeOffset startDate, DateTimeOffset endDate)
    {
        TimeSpan span = endDate.Subtract(startDate);

        if (span.TotalSeconds < 60)
        {
            return $"{Math.Round(span.TotalSeconds, 0)} sec ago";
        }
        else if (span.TotalMinutes < 60)
        {
            return $"{Math.Round(span.TotalMinutes, 0)} min ago";
        }
        else if (span.TotalHours < 24)
        {
            return $"{Math.Round(span.TotalHours, 1)} hrs ago";
        }
        else if (span.TotalDays < 365)
        {
            return $"{Math.Round(span.TotalDays, 1)} days ago";
        }
        else
        {
            return $"{Math.Round(span.TotalDays / 365, 1)} years ago";
        }
    }
    public static async Task<bool> IsLoggedInAsync(string token)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
        {
            return false;
        }
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM logins WHERE Token = @Token";
            command.Parameters.AddWithValue("@Token", token);
            var reader = await command.ExecuteReaderAsync();
            await reader.ReadAsync();
            return reader.HasRows;
        }
    }
    public static async Task<User> GetLoggedInUserAsync(string token)
    {
        if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
        {
            return new User();
        }
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM logins WHERE Token = @Token";
            command.Parameters.AddWithValue("@Token", token);
            var reader = await command.ExecuteReaderAsync();
            await reader.ReadAsync();
            if (!reader.HasRows)
            {
                return new User();
            }
            var userCommand = connection.CreateCommand();
            userCommand.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
            userCommand.Parameters.AddWithValue("@UUID", reader.GetString(0));
            var userReader = await userCommand.ExecuteReaderAsync();
            await userReader.ReadAsync();
            if (!userReader.HasRows)
            {
                return new User();
            }
            return new User
            {
                UID = userReader.GetString(0),
                UUID = userReader.GetString(1),
                Username = userReader.GetString(2),
                PasswordHash = userReader.GetString(3),
                CreationDate = userReader.GetString(4),
                LastLoginDate = userReader.GetString(5),
                Type = userReader.GetInt32(6),
                State = userReader.GetInt32(7)
            };
        }
    }
    public static async Task<Punishment> GetPunishmentAsync(string UUID)
    {
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM punishedUsers WHERE UUID = @UUID";
            command.Parameters.AddWithValue("@UUID", UUID);
            var reader = await command.ExecuteReaderAsync();
            await reader.ReadAsync();
            if (!reader.HasRows || reader.IsDBNull(3))
            {
                return new Punishment();
            }
            return new Punishment
            {
                UUID = reader.GetString(0),
                State = reader.GetInt32(1),
                Reason = reader.GetString(2),
                ExpirationDate = long.Parse(reader.GetString(3)),
                Punisher = reader.GetString(4)
            };
        }
    }
    public static async Task<User> GetUserFromUUID(string UUID)
    {
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
            command.Parameters.AddWithValue("@UUID", UUID);
            var reader = await command.ExecuteReaderAsync();
            await reader.ReadAsync();
            if (!reader.HasRows)
            {
                return new User();
            }
            return new User
            {
                UID = reader.GetString(0),
                UUID = reader.GetString(1),
                Username = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                CreationDate = reader.GetString(4),
                LastLoginDate = reader.GetString(5),
                Type = reader.GetInt32(6),
                State = reader.GetInt32(7)
            };
        }
    }
    public static async Task<User> UnbanUUIDAsync(string UUID)
    {
        User user = new User();
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM punishedUsers WHERE UUID = @UUID";
            command.Parameters.AddWithValue("@UUID", UUID);
            await command.ExecuteNonQueryAsync();
            var userCommand = connection.CreateCommand();
            userCommand.CommandText = "UPDATE users SET State = 0 WHERE UUID = @UUID";
            userCommand.Parameters.AddWithValue("@UUID", UUID);
            await userCommand.ExecuteNonQueryAsync();
            var selectCommand = connection.CreateCommand();
            selectCommand.CommandText = "SELECT * FROM users WHERE UUID = @UUID";
            selectCommand.Parameters.AddWithValue("@UUID", UUID);
            var reader = await selectCommand.ExecuteReaderAsync();
            await reader.ReadAsync();
            user = new User
            {
                UID = reader.GetString(0),
                UUID = reader.GetString(1),
                Username = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                CreationDate = reader.GetString(4),
                LastLoginDate = reader.GetString(5),
                Type = reader.GetInt32(6),
                State = reader.GetInt32(7)
            };
        }
        return user;
    }
    public static async Task InitializeAsync()
    {
        if (!File.Exists("pastes.sqlite"))
        {
            File.Create("pastes.sqlite").Close();
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE pastes (UID INTEGER,Title TEXT, Date TEXT, Size TEXT, Visibility TEXT, ID TEXT,Uploader TEXT, PasswordHash TEXT, PRIMARY KEY(UID AUTOINCREMENT))";
                await command.ExecuteNonQueryAsync();

                var usersTableCommand = connection.CreateCommand();
                usersTableCommand.CommandText = "CREATE TABLE users (UID INTEGER,UUID TEXT,Username TEXT,PasswordHash TEXT,CreationDate TEXT,LastLoginDate TEXT,Type INTEGER,State INTEGER, PRIMARY KEY(UID AUTOINCREMENT))";
                await usersTableCommand.ExecuteNonQueryAsync();

                var loginsTableCommand = connection.CreateCommand();
                loginsTableCommand.CommandText = "CREATE TABLE logins (UUID TEXT,UserAgent TEXT,IP TEXT,LoginTime TEXT,ExpireTime TEXT, Token TEXT)";
                await loginsTableCommand.ExecuteNonQueryAsync();

                var punishedUsersTableCommand = connection.CreateCommand();
                punishedUsersTableCommand.CommandText = "CREATE TABLE punishedUsers (UUID TEXT,Username TEXT,State INTEGER,Reason TEXT,ExpirationDate TEXT";
                await punishedUsersTableCommand.ExecuteNonQueryAsync();
            }
        }
        if (File.Exists("config.json"))
        {
            var config = JObject.Parse(File.ReadAllText("config.json"));
            cfTurnstileSecret = config["CF_TurnstileSecret"]?.ToString() ?? "";
            cfTurnstileSiteKey = config["CF_TurnstileSiteKey"]?.ToString() ?? "";

            File.WriteAllText("config.json", config.ToString());
        }
        if (cfTurnstileSiteKey == "" || cfTurnstileSecret == "")
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("error: ");
            Console.ResetColor();
            Console.WriteLine("Cloudflare Turnstile secret or site key is not set in config.json");
            Console.ReadKey();
            Environment.Exit(1);
        }
        if (!Directory.Exists("pastes"))
            Directory.CreateDirectory("pastes");
    }
    public static string GenerateRandomString(int length)
    {
        var random = new Random();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return new string(Enumerable.Repeat(chars, length)
          .Select(s => s[random.Next(s.Length)]).ToArray());
    }
    public static string GenerateRandomPassword(int length)
    {
       var random = new Random();
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
        return new string(Enumerable.Repeat(chars, length)
          .Select(s => s[random.Next(s.Length)]).ToArray());
    }
}
public class Paste
{
    public string? Title { get; set; }
    public string? Content { get; set; }
    public string? Size { get; set; }
    public long? UnixDate { get; set; }
    public string? Visibility { get; set; }
    public string? Id { get; set; }
    public long? UID { get; set; }
    public string? Uploader { get; set; }
}
public class PrivatePaste : Paste
{
    public string? PasswordHash { get; set; }
}
public class User
{
    public string? UID { get; set; }
    public string? UUID { get; set; }
    public string? Username { get; set; }
    public string? PasswordHash { get; set; }
    public string? CreationDate { get; set; }
    public string? LastLoginDate { get; set; }
    public int Type { get; set; }
    public int State { get; set; }
}
public class Punishment
{
    public string? UUID { get; set; }
    public int State { get; set; }

    public string? Reason { get; set; }
    public long? ExpirationDate { get; set; }
    public string? Punisher { get; set; }

}

