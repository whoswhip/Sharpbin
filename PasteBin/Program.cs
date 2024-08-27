using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using System.Threading.RateLimiting;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Text;
using Sharpbin;
using System.Security.Cryptography;

class Program
{
    private static string salt = string.Empty;
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

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseRateLimiter();

        app.UseAuthorization();

        app.MapRazorPages();

        #region Frontend

        app.MapGet("/", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets\\index.html");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                var user = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                if (user.State != 0)
                {
                    context.Response.Redirect("/banned");
                    return;
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
        app.MapGet("/login", async (HttpContext context) =>
        {
            if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                context.Response.Redirect("/");
                return;
            }
            var html = File.ReadAllText("assets\\login.html");
            html = html.Replace("{html}", "<a href=\"/sign-up\">sign up</a>");
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
            var html = File.ReadAllText("assets\\signup.html");
            html = html.Replace("{html}", "<a href=\"/login\">login</a>");
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

            var html = File.ReadAllText("assets\\dash.html");
            if (user.Type == 255)
            {
                html = File.ReadAllText("assets\\admin.html");
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var usersCommand = connection.CreateCommand();
                    usersCommand.CommandText = "SELECT * FROM users";
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
            var error_html = File.ReadAllText("assets\\error.html");
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
            var error_html = File.ReadAllText("assets\\error.html");
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
            var error_html = File.ReadAllText("assets\\error.html");
            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                var user = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                if (user.State != 1)
                {
                    context.Response.Redirect("/unauthorized");
                    return;
                }
                error_html = error_html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                error_html = error_html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
            }
            error_html = error_html.Replace("{code}", "403");
            error_html = error_html.Replace("{message}", "You are banned");
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
            var content = File.ReadAllText($"pastes/{id}.txt");
            content = content.Replace("\n", "<br>").Replace("\r", "");
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
                if (paste.Uploader.Contains("Anonymous"))
                {
                    user.Username = "Anonymous";
                }
                else
                {
                    user.Username = $"<a class=\"user-a\" href=\"/u/{user.Username}\">{user.Username}</a>";
                }
                if (paste.Visibility == "Private")
                {
                    // WIP Private pastes will be implemented soon enough, most likely with a password or longer ID
                    context.Response.StatusCode = 404;
                    return;
                }
                if (paste.Title == "" || string.IsNullOrEmpty(paste.Title))
                {
                    paste.Title = $"Untitled {reader.GetString(0)}";
                }
                if (paste.Title.Length > 40)
                {
                    paste.Title = paste.Title.Substring(0, 50) + "...";
                }


                var html = File.ReadAllText("assets\\paste.html");
                html = html.Replace("{pastetitle}", paste.Title);
                html = html.Replace("{content}", content);
                html = html.Replace("{pasteid}", paste.Id);
                html = html.Replace("{username}", user.Username);
                html = html.Replace("{creationdate}", paste.UnixDate.ToString());
                html = html.Replace("{pastesize}", ConvertToBytes(paste.Size));
                if (paste.Uploader == loggedInUser.UUID || loggedInUser.Type == 255)
                {
                    html = html.Replace("{deletebutton}", "<button id=\"delete-button\" class=\"button\">delete</button>");
                    html = html.Replace("{deletescript}", "    document.getElementById(\"delete-button\").addEventListener(\"click\", function () {\r\n        alert(\"Deletion cannot be undone. Are you sure you want to delete this paste?\");\r\n        var requestUrl = \"/api/pastes/delete\";\r\n        fetch(requestUrl, {\r\n            method: \"POST\",\r\n            headers: {\r\n                \"Content-Type\": \"application/json\",\r\n            },\r\n            body: JSON.stringify({\r\n                id: \"" + paste.Id + "\"\r\n            })\r\n        })\r\n            .then(response => response.json())\r\n            .then(obj => {\r\n                const result = JSON.parse(obj);\r\n                if (result.message != null) {\r\n                    window.location.href = `/`;\r\n                }\r\n            })\r\n    });");
                }
                else
                {
                    html = html.Replace("{deletebutton}", "");
                    html = html.Replace("{deletescript}", "");
                }
                bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);

                if (loggedIn)
                {
                    html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
                }
                else
                {
                    html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
                }

                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
                return;
            }
        });
        app.MapGet("/raw/{id}", async (HttpContext context) =>
        {
            var id = context.Request?.RouteValues?["id"]?.ToString();
            if (!File.Exists($"pastes/{id}.txt"))
            {
                context.Response.StatusCode = 404;
                return;
            }
            var content = File.ReadAllText($"pastes/{id}.txt");
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync(content);
            return;
        });
        app.MapGet("/pastes", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets\\recent_pastes.html");
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
                        title = paste.Title.Substring(0, 50) + "...";
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
            var html = File.ReadAllText("assets\\archives.html");
            var page = context.Request?.Query["page"].ToString();

            bool loggedIn = await IsLoggedInAsync(context.Request.Cookies["token"]);
            if (loggedIn)
            {
                html = html.Replace("{html}", "<a href=\"/dash\">dashboard</a>");
            }
            else
            {
                html = html.Replace("{html}", "<a href=\"/login\">login</a> <a href=\"/sign-up\">sign up</a>");
            }

            int pageNumber;
            if (!int.TryParse(page, out pageNumber) || pageNumber <= 0)
            {
                pageNumber = 1;
            }
            int pastesPerPage = 50;
            int skipCount = (pageNumber - 1) * pastesPerPage;

            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = $"SELECT * FROM pastes WHERE Visibility != 'Private' ORDER BY UID DESC LIMIT {pastesPerPage} OFFSET {skipCount}";
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
                        title = paste.Title.Substring(0, 50) + "...";
                    }
                    var difference = GetTimeDifference(DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0), DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.Now.ToUnixTimeSeconds()));
                    pastes += $"<a title=\"{paste.Title}\" href=\"/{paste.Id}\"><li>{title} {difference} {ConvertToBytes(paste.Size)}</li></a>";
                }
                var findCountCommand = connection.CreateCommand();
                findCountCommand.CommandText = "SELECT COUNT(*) FROM pastes WHERE Visibility != 'Private'";
                int totalPastes = Convert.ToInt32(await findCountCommand.ExecuteScalarAsync());
                int totalPages = (int)Math.Ceiling((double)totalPastes / pastesPerPage);

                if (pageNumber > totalPages && totalPages != 0)
                {
                    context.Response.Redirect($"/archive?page={totalPages}");
                    return;
                }
                if (string.IsNullOrEmpty(pastes))
                {
                    pastes = "<h2>No pastes found</h1>";
                    html = html.Replace("</style>", "");
                    html = html.Replace("</html>", "");
                    html += ".buttons-wrapper{\r\n    display: none !important;\r\n}";
                    html += "</style>\n</html>";
                }
                html = html.Replace("{pastes}", pastes);
                html = html.Replace("{backpagenum}", $"{pageNumber - 1}");
                html = html.Replace("{pagenum}", $"{pageNumber + 1}");
                html = html.Replace("{currentpagenum}", $"{pageNumber}");
                html = html.Replace("{totalpages}", $"{totalPages}");
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
                return;
            }
        }).RequireRateLimiting("fixed-bigger");
        app.MapGet("/u/{username}", async (HttpContext context) =>
        {
            string username = context.Request?.RouteValues?["username"]?.ToString();
            var html = File.ReadAllText(@"assets\user.html");
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
                    html = File.ReadAllText(@"assets\error.html");
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
        });
        app.MapGet("/uid/{uid}", async (HttpContext context) =>
        {
            string username = context.Request?.RouteValues?["uid"]?.ToString();
            var html = File.ReadAllText(@"assets\user.html");
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
                    html = File.ReadAllText(@"assets\error.html");
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
        });

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

            var html = File.ReadAllText(@"assets\admin\user.html");
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
                    html = File.ReadAllText(@"assets\error.html");
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
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            else if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                
                if (loggedInUser.Type != 255)
                {
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }
            }
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var uuid = SanitizeInput(data["uuid"]?.ToString() ?? "");
            var reason = SanitizeInput(data["reason"]?.ToString() ?? "No reason provided");
            if (string.IsNullOrEmpty(uuid) || string.IsNullOrWhiteSpace(uuid))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
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
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "User not found" }.ToString());
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
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "User is already banned" }.ToString());
                    return;
                }
                if (user.Type == 255)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Cannot ban an admin" }.ToString());
                    return;
                }
                var banUserCommand = connection.CreateCommand();
                banUserCommand.CommandText = "UPDATE users SET State = 1 WHERE UUID = @UUID";
                banUserCommand.Parameters.AddWithValue("@UUID", uuid);
                await banUserCommand.ExecuteNonQueryAsync();

                var punishedUsersCommand = connection.CreateCommand();
                punishedUsersCommand.CommandText = "INSERT INTO punishedUsers (UUID,State, Reason, Punisher) VALUES (@UUID, @State, @Reason, @Punisher)";
                punishedUsersCommand.Parameters.AddWithValue("@UUID", uuid);
                punishedUsersCommand.Parameters.AddWithValue("@State", 1);
                punishedUsersCommand.Parameters.AddWithValue("@Reason", reason);
                punishedUsersCommand.Parameters.AddWithValue("@Punisher", loggedInUser.UUID);
                await punishedUsersCommand.ExecuteNonQueryAsync();
            }
            Console.WriteLine($"[{DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}] Account {user.Username}({user.UUID}) has been banned by {loggedInUser.Username}({loggedInUser.UUID}) for {reason}");
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(new JObject { ["message"] = "User banned" }.ToString());
            return;
        });

        #endregion

        #endregion

        #region API

        app.MapPost("/api/pastes/create", async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            string ip = context.Request.Headers["X-Forwarded-For"].ToString() ?? context.Connection.RemoteIpAddress.ToString();
            string uploaderUUID = string.Empty;
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "No content uploaded" }.ToString());
                return;
            }
            if (await IsLoggedInAsync(context.Request.Cookies["token"]))
            {
                using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
                {
                    await connection.OpenAsync();
                    var command = connection.CreateCommand();
                    command.CommandText = "SELECT * FROM logins WHERE Token = @Token";
                    command.Parameters.AddWithValue("@Token", context.Request.Cookies["token"]);
                    var reader = await command.ExecuteReaderAsync();
                    await reader.ReadAsync();
                    uploaderUUID = reader.GetString(0);
                    var user = await GetLoggedInUserAsync(context.Request.Cookies["token"]);
                    if (user.State != 0)
                    {
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "User is banned" }.ToString());
                        return;
                    }
                }
            }
            else
            {
                uploaderUUID = $"Anonymous-{Guid.NewGuid().ToString()}";
            }

            var data = JObject.Parse(requestBody);
            var title = SanitizeInput(data["title"]?.ToString() ?? "Untitled");
            var content = SanitizeInput(data["content"]?.ToString() ?? "");
            var visibility = SanitizeInput(data["visibility"]?.ToString() ?? "Public");

            if (content.Length > 500_000 || title.Length > 500)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Content or Title is too long" }.ToString());
                return;
            }

            if (visibility != "Public" && visibility != "Unlisted" && visibility != "Private")
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid visibility" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(content) || string.IsNullOrWhiteSpace(content))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var paste = await CreatePaste(content, title, visibility, uploaderUUID);

            if (!File.Exists($"pastes/{paste?.Id}.txt") || paste == null)
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Failed to create paste" }.ToString());
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";

            string time = DateTimeOffset.FromUnixTimeSeconds(paste.UnixDate ?? 0).DateTime.ToString("yyyy-MM-dd HH:mm:ss");

            JObject responseJson = new JObject();
            responseJson["pasteId"] = paste.Id;
            responseJson["pasteSize"] = ConvertToBytes(paste.Size ?? string.Empty);
            responseJson["pasteDate"] = time;
            responseJson["pasteVisibility"] = paste.Visibility;

            Log log = await Logging.LogRequestAsync(context);

            Console.WriteLine($"[{time}] Paste created, {ConvertToBytes(paste.Size ?? string.Empty)}, {paste.Id} by {uploaderUUID}");
            await File.AppendAllTextAsync("logs.log", $"[{time}] {paste.Id} {log.IP} {log.Method} {log.Path} {log.UserAgent} {log.Referer} {log.Body} {uploaderUUID}\n");

            await context.Response.WriteAsJsonAsync(responseJson.ToString());
            return;

        }).RequireRateLimiting("fixed");
        app.MapPost("/api/pastes/delete", async (HttpContext context) =>
        {
            string token = context.Request.Cookies["token"] ?? context.Request.Headers["Authorization"];
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (!await IsLoggedInAsync(token))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var id = SanitizeInput(data["id"]?.ToString() ?? "");
            if (string.IsNullOrEmpty(id) || string.IsNullOrWhiteSpace(id))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
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
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Paste not found" }.ToString());
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

                if (verifyReader.GetString(0) != UUID || user.Type != 255)
                {
                    Console.WriteLine(verifyReader.GetString(1) + "  " + UUID);
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Unauthorized" }.ToString());
                    return;
                }


                var deleteCommand = connection.CreateCommand();
                deleteCommand.CommandText = "DELETE FROM pastes WHERE ID = @ID";
                deleteCommand.Parameters.AddWithValue("@ID", id);
                await deleteCommand.ExecuteNonQueryAsync();
                File.Delete($"pastes/{id}.txt");
                await context.Response.WriteAsJsonAsync(new JObject { ["message"] = "Paste deleted" }.ToString());
            }

        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/create", async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            Log log = await Logging.LogRequestAsync(context);

            char[] disallowed = { ' ', '\'', '\"', '\\', '/', '(', ')', '[', ']', '{', '}', '<', '>', ';', ':', ',', '.', '!', '?', '@', '#', '$', '%', '^', '&', '*', '-', '+', '=', '~', '`' };

            if (IsLoggedInAsync(context.Request.Cookies["token"]).Result)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Already logged in" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            if (!requestBody.Contains("username") || !requestBody.Contains("password") || context.Request.ContentType != "application/json")
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var data = JObject.Parse(requestBody);
            var username = SanitizeInput(data["username"]?.ToString() ?? "");
            var password = SanitizeInput(data["password"]?.ToString() ?? "");

            if (username.Length > 20 || username.Length < 3 || password.Length > 50 || password.Length < 8)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid username or password length" }.ToString());
                return;
            }
            if (username.IndexOfAny(disallowed) != -1)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid characters in username" }.ToString());
                return;
            }
            string ip = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes(log.IP)));
            string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString())));
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, salt);
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
                    await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Username already exists" }.ToString());
                    return;
                }
                else if (!reader.HasRows && !reader.IsClosed)
                {
                    reader.Close();
                }
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
            Console.WriteLine($"[{DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}] Account {username} has been created");
            File.AppendAllText("logs.log", $"[{DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}] Account {username} has been created by {log.IP}\n");
            await context.Response.WriteAsJsonAsync(new JObject { ["message"] = "Account created" }.ToString());


        }).RequireRateLimiting("fixed");
        app.MapPost("/api/accounts/login", async (HttpContext Context) =>
        {
            string requestBody = await new StreamReader(Context.Request.Body).ReadToEndAsync();
            Log log = await Logging.LogRequestAsync(Context);

            if (IsLoggedInAsync(Context.Request.Cookies["token"]).Result)
            {
                Context.Response.StatusCode = 400;
                Context.Response.ContentType = "application/json";
                await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Already logged in" }.ToString());
                return;
            }
            if (string.IsNullOrEmpty(requestBody))
            {
                Context.Response.StatusCode = 400;
                Context.Response.ContentType = "application/json";
                await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "No data uploaded" }.ToString());
                return;
            }
            if (!requestBody.Contains("username") || !requestBody.Contains("password") || Context.Request.ContentType != "application/json")
            {
                Context.Response.StatusCode = 400;
                Context.Response.ContentType = "application/json";
                await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var data = JObject.Parse(requestBody);
            var username = SanitizeInput(data["username"]?.ToString() ?? "");
            var password = SanitizeInput(data["password"]?.ToString() ?? "");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                Context.Response.StatusCode = 400;
                Context.Response.ContentType = "application/json";
                await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                return;
            }

            string ip = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes(log.IP)));
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
                    Context.Response.StatusCode = 400;
                    Context.Response.ContentType = "application/json";
                    await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                    return;
                }
                if (BCrypt.Net.BCrypt.Verify(password, reader.GetString(3)))
                {
                    string token = Convert.ToBase64String(Encoding.UTF8.GetBytes(BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString())));
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

                    Context.Response.Cookies.Append("token", token, cookie);
                    Context.Response.StatusCode = 200;
                    Context.Response.ContentType = "application/json";
                    Console.WriteLine($"[{DateTime.Now}] Account {username} has logged in");
                    File.AppendAllText("logs.log", $"[{DateTime.Now}] Account {username} has logged in from {log.IP}\n");
                    await Context.Response.WriteAsJsonAsync(new JObject { ["message"] = "Logged in" }.ToString());
                    return;
                }
                else
                {
                    Context.Response.StatusCode = 400;
                    Context.Response.ContentType = "application/json";
                    await Context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid username or password" }.ToString());
                }
            }
        }).RequireRateLimiting("fixed");

        #endregion

        await app.RunAsync();
    }

    public static async Task<Paste> CreatePaste(string content, string title, string visibility, string UUID)
    {
        var paste = new Paste
        {
            Content = content,
            Title = title,
            UnixDate = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Size = content.Length.ToString(),
            Visibility = visibility,
            Id = GenerateRandomString(12),
            Uploader = UUID
        };
        await File.WriteAllTextAsync($"pastes/{paste.Id}.txt", paste.Content);
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
    public static async Task InitializeAsync()
    {
        if (!File.Exists("pastes.sqlite"))
        {
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE pastes (UID INTEGER,Title TEXT, Date TEXT, Size TEXT, Visibility TEXT, ID TEXT,Uploader TEXT, PRIMARY KEY(UID AUTOINCREMENT))";
                await command.ExecuteNonQueryAsync();

                var usersTableCommand = connection.CreateCommand();
                usersTableCommand.CommandText = "CREATE TABLE users (UID INTEGER,UUID TEXT,Username TEXT,PasswordHash TEXT,CreationDate TEXT,LastLoginDate TEXT,Type INTEGER,State INTEGER, PRIMARY KEY(UID AUTOINCREMENT))";
                await usersTableCommand.ExecuteNonQueryAsync();

                var loginsTableCommand = connection.CreateCommand();
                loginsTableCommand.CommandText = "CREATE TABLE logins (UUID TEXT,UserAgent TEXT,IP TEXT,LoginTime TEXT,ExpireTime TEXT, Token TEXT)";
                await loginsTableCommand.ExecuteNonQueryAsync();

                var punishedUsersTableCommand = connection.CreateCommand();
                punishedUsersTableCommand.CommandText = "CREATE TABLE punished_users (UUID TEXT,Username TEXT,State INTEGER,Reason TEXT,ExpirationDate TEXT";
                await punishedUsersTableCommand.ExecuteNonQueryAsync();
            }
        }
        if (File.Exists("config.json"))
        {
            var config = JObject.Parse(File.ReadAllText("config.json"));
            salt = config["Salt"]?.ToString() ?? BCrypt.Net.BCrypt.GenerateSalt(13);
            Logging.Api_CreateMessage = config["API_CreateMessage"]?.ToString() ?? "";
        }
        else
        {
            var config = new JObject();
            config["Salt"] = BCrypt.Net.BCrypt.GenerateSalt(13);
            salt = config["Salt"]?.ToString() ?? BCrypt.Net.BCrypt.GenerateSalt(13);
            File.WriteAllText("config.json", config.ToString());
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
}
public class Paste
{
    public string? Title { get; set; }
    public string? Content { get; set; }
    public string? Size { get; set; }
    public long? UnixDate { get; set; }
    public string? Visibility { get; set; }
    public string? Id { get; set; }
    public string? Uploader { get; set; }
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

