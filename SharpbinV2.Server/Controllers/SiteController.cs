using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SharpbinV2.Server.Services;

namespace SharpbinV2.Server.Controllers
{
    [ApiController]
    [Route("api/site")]
    public class SiteController : Controller
    {
        private readonly ILogger<SiteController> _logger;
        private readonly DatabaseService _databaseService;
        public SiteController(ILogger<SiteController> logger, DatabaseService databaseService)
        {
            _logger = logger;
            _databaseService = databaseService;
        }

        [HttpGet("info")]
        [EnableRateLimiting("general")]
        public IActionResult GetInfo()
        {
            var info = new
            {
               Program.MaxFileSize,
            };
            return Ok(new { success = true, info });
        }
    }
}
