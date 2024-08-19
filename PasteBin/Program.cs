using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using System.Threading.RateLimiting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Components.Web;

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
                command.CommandText = "CREATE TABLE pastes (UID INTEGER,Title TEXT, Date TEXT, Size TEXT, ID TEXT, PRIMARY KEY(UID AUTOINCREMENT))";
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

        app.MapGet("/", async (HttpContext context) =>
        {
            var html = File.ReadAllText("assets\\index.html");
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync(html);
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
            using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM pastes WHERE ID = @ID";
                command.Parameters.AddWithValue("@ID", id);
                var reader = await command.ExecuteReaderAsync();
                await reader.ReadAsync();
                var paste = new Paste
                {
                    Title = reader.GetString(1),
                    Date = reader.GetString(2),
                    Size = reader.GetString(3),
                    Id = id,
                };
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
        app.MapPost("/api/create", async (HttpContext context) =>
        {
            string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
            if (requestBody.Length > 10000 || string.IsNullOrEmpty(requestBody))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }
            var data = JObject.Parse(requestBody);
            var title = SanitizeInput(data["title"]?.ToString() ?? "Untitled");
            var content = SanitizeInput(data["content"]?.ToString() ?? "");
            if(string.IsNullOrEmpty(content))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new JObject { ["error"] = "Invalid request body" }.ToString());
                return;
            }

            var paste = await CreatePaste(content, title);

            if (!File.Exists($"pastes/{paste?.Id}.txt") || paste == null)
            {
                context.Response.StatusCode = 500;
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";

            JObject responseJson = new JObject();
            responseJson["pasteId"] = paste.Id;
            responseJson["pasteSize"] = paste.Size;
            responseJson["pasteDate"] = paste.Date;

            await context.Response.WriteAsJsonAsync(responseJson.ToString());
            return;

        }).RequireRateLimiting("fixed");

        await app.RunAsync();
    }

    public static async Task<Paste> CreatePaste(string content, string title)
    {
        var paste = new Paste
        {
            Content = content,
            Title = title,
            Date = DateTime.Now.ToString("dd/MM/yyyy-HH:mm:ss"),
            Size = ConvertToBytes(content.Length.ToString()),
            Id = GenerateRandomString(12)
        };
        File.WriteAllText($"pastes/{paste.Id}.txt", paste.Content);
        using (var connection = new SqliteConnection("Data Source=pastes.sqlite"))
        {
            await connection.OpenAsync();
            var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO pastes (Title, Date, Size, ID) VALUES (@Title, @Date, @Size, @ID)";
            command.Parameters.AddWithValue("@Title", paste.Title);
            command.Parameters.AddWithValue("@Date", paste.Date);
            command.Parameters.AddWithValue("@Size", paste.Size);
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
    public string? Id { get; set; }
}
