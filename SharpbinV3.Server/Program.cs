using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Settings;
using System.Text;
using System.Threading.RateLimiting;

namespace SharpbinV3.Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var connectionString = Environment.GetEnvironmentVariable("SQLITE_CONN") 
                       ?? builder.Configuration.GetConnectionString("Default");

            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();
            builder.Services.AddDbContext<AppDbContext>(opt =>
            {
                opt.UseSqlite(connectionString);
            });
            builder.Services.AddSingleton<ICompressionService, CompressionService>();
            builder.Services.AddSingleton<IHostedService, PasteCleanUpService>();
            builder.Services.AddScoped<IUserService, UserService>();
            builder.Services.AddScoped<IAuthService, AuthService>();
            builder.Services.AddScoped<IPasteService, PasteService>();

            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwt =>
                {
                    var jwtSettings = builder.Configuration.GetSection("JwtSettings");
                    var key = Encoding.UTF8.GetBytes(jwtSettings["Secret"]!);

                    jwt.SaveToken = true;
                    jwt.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),

                        ValidateIssuer = true,
                        ValidIssuer = jwtSettings["Issuer"],

                        ValidateAudience = true,
                        ValidAudience = jwtSettings["Audience"],

                        RequireExpirationTime = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,

                        RequireSignedTokens = true,
                        ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
                    };
                });


            builder.Services.AddRateLimiter(options =>
            {
                options.AddSlidingWindowLimiter("Sliding", opt =>
                {
                    opt.Window = TimeSpan.FromSeconds(10);
                    opt.PermitLimit = 10;
                    opt.QueueLimit = 2;
                    opt.SegmentsPerWindow = 5;
                    opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                });

                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            });
            builder.Services.AddCors(o =>
            {
                o.AddDefaultPolicy(p =>
                    p.WithOrigins("http://localhost:5173")
                     .AllowAnyHeader()
                     .AllowAnyMethod());
            });
            builder.Services.Configure<PasteSettings>(builder.Configuration.GetSection("PasteSettings"));
            builder.Services.Configure<JWTSettings>(builder.Configuration.GetSection("JWTSettings"));

            var app = builder.Build();
            app.UseRateLimiter();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                db.Database.Migrate();
            }

            app.Run();
        }
    }
}
