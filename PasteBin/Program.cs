using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using System.Threading.RateLimiting;
using Newtonsoft.Json.Linq;
using System.Data;
using System.Runtime.InteropServices;

class Program
{
    public static async Task Main(string[] args)
    {
        if(!File.Exists("pastes.sqlite"))
        {
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE pastes (UID INTEGER,Title TEXT, Date TEXT, Size TEXT, Visibility TEXT, ID TEXT, PRIMARY KEY(UID AUTOINCREMENT))";
                await command.ExecuteNonQueryAsync();
            }
        }
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
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
            return;
        });
        app.MapGet("/paste-not-found", async (HttpContext context) =>
        {
            context.Response.StatusCode = 404;
            var error_html = File.ReadAllText("assets\\error.html");
            error_html = error_html.Replace("{code}", "404");
            error_html = error_html.Replace("{message}", "Paste not found");
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(error_html);
            return;
        });
        app.MapGet("/{id}", async (HttpContext context) =>
        {
            var id = context.Request?.RouteValues?["id"]?.ToString();
            if (!File.Exists($"pastes/{id}.txt"))
            {
                context.Response.StatusCode = 404;
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
                if(!reader.HasRows)
                {
                    context.Response.StatusCode = 404;
                    context.Response.Redirect("/paste-not-found");
                    return;
                }
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    Date = reader.GetString(2),
                    Size = reader.GetString(3),
                    Visibility = reader.GetString(4),
                    Id = id,
                };
                if(paste.Visibility == "Private")
                {
                    // WIP Private pastes will be implemented soon enough, most likely with a password or longer ID
                    context.Response.StatusCode = 404;
                    return;
                }
                var html = File.ReadAllText("assets\\paste.html");
                html = html.Replace("{pastetitle}", paste.Title);
                html = html.Replace("{content}", content);
                html = html.Replace("{pasteid}", paste.Id);
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
                        Date = reader.GetString(2),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = reader.GetString(5),
                    };
                    if(paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                    {
                        continue;
                    }
                    if(paste.Title == "" || string.IsNullOrEmpty(paste.Title))
                    {
                        paste.Title = $"Untitled {reader.GetString(0)}";
                    }
                    pastes += $"<a href=\"/{paste.Id}\"><li>{paste.Title} {paste.Date} {ConvertToBytes(paste.Size)}</li></a>";
                }
                if(string.IsNullOrEmpty(pastes))
                {
                    pastes = "<h2>No pastes found</h1>";
                }
                html = html.Replace("{pastes}", pastes);
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync(html);
                return;
            }
        }).RequireRateLimiting("fixed");
        app.MapGet("/archive", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets\\archives.html");
            var page = context.Request?.Query["page"].ToString();

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
                        Date = reader.GetString(2),
                        Size = reader.GetString(3),
                        Visibility = reader.GetString(4),
                        Id = reader.GetString(5),
                    };
                    if(paste.Visibility == "Private" || paste.Visibility == "Unlisted")
                    {
                        continue;
                    }
                    if (paste.Title == "" || string.IsNullOrEmpty(paste.Title))
                    {
                        paste.Title = $"Untitled {reader.GetString(0)}";
                    }
                    pastes += $"<a href=\"/{paste.Id}\"><li>{paste.Title} {paste.Date} {ConvertToBytes(paste.Size)}</li></a>";
                }
                var findCountCommand = connection.CreateCommand();
                findCountCommand.CommandText = "SELECT COUNT(*) FROM pastes WHERE Visibility != 'Private'";
                int totalPastes = Convert.ToInt32(await findCountCommand.ExecuteScalarAsync() );
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


        #endregion

        #region API

        app.MapPost("/api/create", async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (requestBody.Length > 500_000 || string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var title = SanitizeInput(data["title"]?.ToString() ?? "Untitled");
            var content = SanitizeInput(data["content"]?.ToString() ?? "");
            var visibility = SanitizeInput(data["visibility"]?.ToString() ?? "Public");

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

            var paste = await CreatePaste(content, title, visibility);

            if (!File.Exists($"pastes/{paste?.Id}.txt") || paste == null)
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Failed to create paste" }.ToString());
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";

            JObject responseJson = new JObject();
            responseJson["pasteId"] = paste.Id;
            responseJson["pasteSize"] = ConvertToBytes(paste.Size ?? string.Empty);
            responseJson["pasteDate"] = paste.Date;
            responseJson["pasteVisibility"] = paste.Visibility;

            Console.WriteLine($"Created a {ConvertToBytes(paste.Size ?? string.Empty)} sized paste with the id of {paste.Id} at {paste.Date}");

            await context.Response.WriteAsJsonAsync(responseJson.ToString());
            return;

        }).RequireRateLimiting("fixed");

        #endregion

        await app.RunAsync();
    }

    public static async Task<Paste> CreatePaste(string content, string title, string visibility)
    {
        var paste = new Paste
        {
            Content = content,
            Title = title,
            Date = DateTime.Now.ToString("dd/MM/yyyy-HH:mm:ss"),
            Size = content.Length.ToString(),
            Visibility = visibility,
            Id = GenerateRandomString(12)
        };
        await File.WriteAllTextAsync($"pastes/{paste.Id}.txt", paste.Content);
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO pastes (Title, Date, Size, Visibility, ID) VALUES (@Title, @Date, @Size, @Visibility, @ID)";
            command.Parameters.AddWithValue("@Title", paste.Title);
            command.Parameters.AddWithValue("@Date", paste.Date);
            command.Parameters.AddWithValue("@Size", paste.Size);
            command.Parameters.AddWithValue("@Visibility", paste.Visibility);
            command.Parameters.AddWithValue("@ID", paste.Id);
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
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        double len = double.Parse(length);
        int order = 0;
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }
        return $"{len:0.##} {sizes[order]}";
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
    public string? Date { get; set; }
    public string? Visibility { get; set; }
    public string? Id { get; set; }
}
