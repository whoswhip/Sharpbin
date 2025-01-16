using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Configuration;
using Microsoft.Extensions.Logging.EventSource;
using Newtonsoft.Json.Linq;
using System.Threading.RateLimiting;
using System.Text;
using Bcrypt = BCrypt.Net.BCrypt;
using System.IO.Compression;
using System.Threading.Tasks;

namespace SharpbinV2.Server
{
    class Program
    {
        public static string MainDatabaseConnection = "Data Source=data.db";
        public static long MaxFileSize = 5000000; // 5MB
        static async Task Main(string[] args)
        {
            await Initialize();
            var logger = new Logging();
            var builder = WebApplication.CreateBuilder(args);
            builder.Configuration.AddEnvironmentVariables();
            builder.WebHost.UseUrls($"https://*:{Environment.GetEnvironmentVariable("HTTPS_Port") ?? "5820"}", $"http://*:{Environment.GetEnvironmentVariable("HTTP_Port") ?? "5810"}");
            MaxFileSize = Environment.GetEnvironmentVariable("MAX_FILE_SIZE") != null ? Convert.ToInt64(Environment.GetEnvironmentVariable("MAX_FILE_SIZE")) : MaxFileSize;

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Limits.MaxRequestBodySize = null;
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

            //app.UseRateLimiter();

            app.UseCors(builder =>
            {
                builder.AllowAnyOrigin();
                builder.AllowAnyMethod();
                builder.AllowAnyHeader();
            });
            app.UseResponseCaching();
            app.UseResponseCompression();

            #region Static Endpoints
            app.MapGet("/", async (HttpContext context) =>
            {
                context.Response.StatusCode = 200;
                context.Response.Headers.Add("Content-Type", "text/html");
                await context.Response.SendFileAsync("assets/index.html");
            });
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
                        command.Parameters.AddWithValue("@Ip", Bcrypt.HashPassword(requestdetails.Ip, Bcrypt.GenerateSalt(10)));
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
            });
            app.MapGet("/api/accounts/login", async (HttpContext context) =>
            {
                var requestdetails = GetRequestDetails(context);
                if (!string.IsNullOrEmpty(requestdetails.Token) && Database.UserFromToken(requestdetails.Token) != null)
                {
                    context.Response.StatusCode = 200;
                    await context.Response.WriteAsJsonAsync(new { success = true, message = "Already logged in." });
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
                        command.Parameters.AddWithValue("@Ip", Bcrypt.HashPassword(requestdetails.Ip, Bcrypt.GenerateSalt(10)));
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
            });

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


                paste.Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                paste.Size = body.Length;
                paste.TrueSize = body.Length;
                paste.UUID = Guid.NewGuid().ToString();
                paste.ID = GenerateRandomString(12);
                paste.AuthorUUID = user?.UUID ?? "0"; // 0 means the user is anonymous
                paste.FilePath = $"pastes/{paste.ID}.txt";
                paste.Visibility = queries.ContainsKey("visibility") ? Convert.ToInt32(queries["visibility"]) : 0;
                paste.Title = queries.ContainsKey("title") ? queries["title"].ToString() : $"Untitled-{await Database.EnumeratePastes()}";
                paste.Edited = 0;

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
                        command.CommandText = "INSERT INTO pastes (UUID, ID, Visibility, Title, AuthorUUID, FilePath, Created, Edited, Size, TrueSize, Views) VALUES (@UUID, @ID, @Visibility, @Title, @AuthorUUID, @FilePath, @Created, @Edited, @Size, @TrueSize, @Views);";
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
                        await command.ExecuteNonQueryAsync();
                    }
                    await connection.CloseAsync();
                }

                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, message = "Paste created.", paste = paste });
                logger.LogInfo($"A Paste of {FormatBytes(paste.Size)} was created by {paste.UUID}");
                return;
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
                if (paste == null)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { success = false, message = "Paste not found." });
                    return;
                }
                context.Response.StatusCode = 200;
                await context.Response.WriteAsJsonAsync(new { success = true, paste = paste });
            });
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

    class Database
    {
        public static async Task<User> UserFromUsername(string username)
        {
            if (string.IsNullOrEmpty(username))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE Username = @Username;";
                    command.Parameters.AddWithValue("@Username", username);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromUUID(string uuid)
        {
            if (string.IsNullOrEmpty(uuid))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE UUID = @UUID;";
                    command.Parameters.AddWithValue("@UUID", uuid);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM users WHERE Email = @Email;";
                    command.Parameters.AddWithValue("@Email", email);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new User
                        {
                            UID = reader.GetInt32(0),
                            UUID = reader.GetString(1),
                            Type = reader.GetInt32(2),
                            Email = reader.IsDBNull(3) ? null : reader.GetString(3),
                            Username = reader.GetString(4),
                            DisplayName = reader.IsDBNull(5) ? null : reader.GetString(5),
                            Password = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            LastLogin = reader.GetInt64(8)
                        };
                    }
                }
            }
        }
        public static async Task<User> UserFromToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {

                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM sessions WHERE Token = @Token;";
                    command.Parameters.AddWithValue("@Token", token);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return await UserFromUUID(reader.GetString(2));
                    }
                }
            }
        }
        public static async Task<int> EnumeratePastes()
        {
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT COUNT(*) FROM pastes;";
                    return Convert.ToInt32(await command.ExecuteScalarAsync());
                }
            }
        }
        public static async Task<Paste> GetPasteFromID(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;
            using (var connection = new SqliteConnection(Program.MainDatabaseConnection))
            {
                await connection.OpenAsync();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = "SELECT * FROM pastes WHERE ID = @ID;";
                    command.Parameters.AddWithValue("@ID", id);
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                            return null;
                        await reader.ReadAsync();
                        return new Paste
                        {
                            UUID = reader.GetString(1),
                            ID = reader.GetString(2),
                            Visibility = reader.GetInt32(3),
                            Title = reader.IsDBNull(4) ? null : reader.GetString(4),
                            AuthorUUID = reader.GetString(5),
                            FilePath = reader.GetString(6),
                            Created = reader.GetInt64(7),
                            Edited = reader.GetInt64(8),
                            Size = reader.GetInt32(9),
                            TrueSize = reader.GetInt32(10),
                            Views = reader.GetInt32(11)
                        };
                    }
                }
            }
        }
    }
    public class Logging
    {
        public Logging()
        {
            if (!Directory.Exists("logs"))
                Directory.CreateDirectory("logs");
        }
        public void LogInfo(string message)
        {
            Console.WriteLine($"[{DateTime.Now} INFO] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} INFO] {message}\n");
        }
        public void LogWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[{DateTime.Now} WARNING] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} WARNING] {message}\n");
            Console.ResetColor();
        }
        public void LogError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[{DateTime.Now} ERROR] {message}");
            File.AppendAllText($"logs/{DateTime.Now.ToString("yyyy-MM-dd")}.log", $"[{DateTime.Now} ERROR] {message}\n");
            Console.ResetColor();
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
    public class Compression
    {
        // Taken from old branch
        public static async Task<byte[]> CompressString(string text)
        {
            byte[] compressedBytes;
            using (var ms = new MemoryStream())
            {
                using (var cs = new GZipStream(ms, CompressionMode.Compress))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                    await cs.WriteAsync(inputBytes, 0, inputBytes.Length);
                }
                compressedBytes = ms.ToArray();
            }
            return compressedBytes;
        }

        public static async Task<string> DecompressByteArrayToString(byte[] compressedBytes)
        {
            string decompressedText;
            using (var ms = new MemoryStream(compressedBytes))
            {
                using (var cs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        decompressedText = await sr.ReadToEndAsync();
                    }
                }
            }
            return decompressedText;
        }

        public static async Task<byte[]> DecompressByteArray(byte[] compressedBytes)
        {
            byte[] decompressedBytes;
            using (var ms = new MemoryStream(compressedBytes))
            {
                using (var cs = new GZipStream(ms, CompressionMode.Decompress))
                {
                    using (var msDecompressed = new MemoryStream())
                    {
                        await cs.CopyToAsync(msDecompressed);
                        decompressedBytes = msDecompressed.ToArray();
                    }
                }
            }
            return decompressedBytes;
        }
        public static async Task<bool> ShouldCompress(string text, int sizeThreshold = 512, double ratioThreshold = 0.8)
        {
            if (string.IsNullOrEmpty(text))
                return false;

            byte[] inputBytes = Encoding.UTF8.GetBytes(text);
            if (inputBytes.Length < sizeThreshold)
                return false;

            byte[] compressedBytes = await CompressString(text).ConfigureAwait(false);
            double compressionRatio = (double)compressedBytes.Length / inputBytes.Length;

            return compressionRatio < ratioThreshold;
        }

        public static bool IsCompressed(byte[] data)
        {
            return data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B;
        }
    }
    class User
    {
        public int UID { get; set; }
        public string UUID { get; set; }
        public int Type { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public string DisplayName { get; set; }
        public string Password { get; set; }
        public long Created { get; set; }
        public long LastLogin { get; set; }
    }
    class Paste
    {
        public string UUID { get; set; }
        public string ID { get; set; }
        public int Visibility { get; set; }
        public string Title { get; set; }
        public string AuthorUUID { get; set; }
        public string FilePath { get; set; }
        public long Created { get; set; }
        public long Edited { get; set; }
        public int Size { get; set; }
        public int TrueSize { get; set; }
        public int Views { get; set; }
    }
    class Session
    {
        public string UUID { get; set; }
        public string UserUUID { get; set; }
        public string Token { get; set; }
        public long Created { get; set; }
        public long Expirary { get; set; }
        public string Ip { get; set; }
        public string UserAgent { get; set; }
    }
    class RequestDetails
    {
        public string Ip { get; set; }
        public string UserAgent { get; set; }
        public string Token { get; set; }
    }
}