using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV2.Server.Services;
using SharpbinV2.Server.Models;

namespace SharpbinV2.Server.Controllers
{
    [ApiController]
    [Route("")]
    public class StaticController : Controller
    {
        private readonly ILogger<StaticController> _logger;
        private readonly DatabaseService _databaseService;
        private readonly IWebHostEnvironment _environment;

        public StaticController(ILogger<StaticController> logger, DatabaseService databaseService, IWebHostEnvironment environment)
        {
            _logger = logger;
            _databaseService = databaseService;
            _environment = environment;
        }

        [HttpGet("")]
        [EnableRateLimiting("general")]
        public IActionResult Index()
        {
            Response.StatusCode = 200;
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "index.html"), "text/html");
        }

        [HttpGet("{pasteid}")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetPaste(string pasteid)
        {
            if (string.IsNullOrWhiteSpace(pasteid))
            {
                return Redirect("/error?error=400&message=Invalid paste id.");
            }

            var filePath = Path.Combine(_environment.WebRootPath, pasteid);
            if (System.IO.File.Exists(filePath))
            {
                var contentType = GetContentType(Path.GetExtension(filePath));
                return PhysicalFile(filePath, contentType);
            }

            var paste = await _databaseService.GetPasteFromID(pasteid);
            if (paste == null)
            {
                return Redirect("/error?error=400&message=Paste not found.");
            }

            var requestDetails = HelperService.GetRequestDetails(HttpContext);
            var user = await _databaseService.UserFromToken(requestDetails.Token ?? "");

            if (user != null)
            {
                if (user.UUID != paste.AuthorUUID)
                {
                    if (!await _databaseService.HasAlreadyViewedFromUserDetails(user))
                    {
                        await _databaseService.AddViewToPaste(user, paste, requestDetails);
                    }
                }
            }
            else
            {
                if (!await _databaseService.AlreadyViewed(requestDetails))
                {
                    await _databaseService.AddViewToPaste(new User { UUID = "0" }, paste, requestDetails);
                }
            }

            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "paste.html"), "text/html");
        }

        [HttpGet("error")]
        public IActionResult Error()
        {
            Response.StatusCode = 400;
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "error.html"), "text/html");
        }

        [HttpGet("error.html")]
        public IActionResult ErrorHtml()
        {
            return Redirect("/error");
        }

        [HttpGet("raw/{pasteid}")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> GetRawPaste(string pasteid)
        {
            if (string.IsNullOrEmpty(pasteid))
            {
                return Redirect("/error?error=400&message=Invalid paste id.");
            }

            var paste = await _databaseService.GetPasteFromID(pasteid);
            if (paste == null || paste.FilePath == null)
            {
                return Redirect("/error?error=400&message=Paste not found.");
            }

            Response.Headers.Append("Content-Type", "text/plain");
            if (paste.FilePath.EndsWith(".gz"))
            {
                Response.Headers.Append("Content-Encoding", "gzip");
            }

            return PhysicalFile(paste.FilePath, "text/plain");
        }

        [HttpGet("paste.html")]
        public IActionResult PasteHtml()
        {
            return Redirect("/");
        }

        [HttpGet("archive")]
        [EnableRateLimiting("general")]
        public IActionResult Archive()
        {
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "archive.html"), "text/html");
        }

        [HttpGet("dash")]
        [EnableRateLimiting("general")]
        public IActionResult Dashboard()
        {
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "dash.html"), "text/html");
        }

        [HttpGet("dash.html")]
        public IActionResult DashboardHtml()
        {
            return Redirect("/dash");
        }

        [HttpGet("login")]
        [EnableRateLimiting("general")]
        public IActionResult Login()
        {
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "login.html"), "text/html");
        }

        [HttpGet("register")]
        [EnableRateLimiting("general")]
        public IActionResult Register()
        {
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "register.html"), "text/html");
        }

        [HttpGet("u/{username}")]
        [EnableRateLimiting("general")]
        public async Task<IActionResult> UserProfile(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                return Redirect("/error?error=400&message=Invalid username.");
            }

            string html = await System.IO.File.ReadAllTextAsync(Path.Combine(_environment.WebRootPath, "user.html"));

            Response.Headers.Append("Content-Type", "text/html");
            Response.Headers.Append("Cache-Control", "no-cache, no-store, must-revalidate");
            Response.Headers.Append("Pragma", "no-cache");
            Response.Headers.Append("Expires", "0");

            return Content(html, "text/html");
        }

        [HttpGet("reset-password")]
        [EnableRateLimiting("general")]
        public IActionResult ResetPassword()
        {
            Response.Headers.Append("Content-Type", "text/html");
            return PhysicalFile(Path.Combine(_environment.WebRootPath, "reset-password.html"), "text/html");
        }

        private static string GetContentType(string extension)
        {
            return extension.ToLowerInvariant() switch
            {
                ".html" => "text/html",
                ".css" => "text/css",
                ".js" => "text/javascript",
                ".json" => "application/json",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".ico" => "image/x-icon",
                _ => "application/octet-stream"
            };
        }
    }
}