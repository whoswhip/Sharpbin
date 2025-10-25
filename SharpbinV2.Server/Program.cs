using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using SharpbinV2.Server.Services;
using System.Security.Cryptography;

namespace SharpbinV2.Server
{
    class Program
    {
        public static string MainDatabaseConnection = "Data Source=data.db";
        public static long MaxFileSize = 1_048_576; // 1MB
        public static string[] ValidSyntaxLanguages =
        [
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
        ];
        public static string SHA256Salt = RandomNumberGenerator.GetHexString(32);

        static async Task Main(string[] args)
        {
            await Initialize();

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

            if (Environment.GetEnvironmentVariable("SHA256_SALT") != null)
            {
                SHA256Salt = Environment.GetEnvironmentVariable("SHA256_SALT") ?? SHA256Salt;
            }
            else
            {
                SHA256Salt = RandomNumberGenerator.GetHexString(32);
                Environment.SetEnvironmentVariable("SHA256_SALT", SHA256Salt);

                var dotenv = Path.Combine(Directory.GetCurrentDirectory(), ".env");
                if (File.Exists(dotenv))
                {
                    var lines = File.ReadAllLines(dotenv).ToList();
                    var saltLine = $"SHA256_SALT={SHA256Salt}";
                    if (lines.Any(line => line.StartsWith("SHA256_SALT=")))
                    {
                        lines[lines.FindIndex(line => line.StartsWith("SHA256_SALT="))] = saltLine;
                    }
                    else
                    {
                        lines.Add(saltLine);
                    }
                    File.WriteAllLines(dotenv, lines);
                }
            }


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

            app.MapControllers();

            await app.RunAsync();

        }

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
                                Fingerprint	TEXT NOT NULL,
                                UserAgent	TEXT,
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