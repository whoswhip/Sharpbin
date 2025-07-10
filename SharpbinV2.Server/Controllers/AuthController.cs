using Microsoft.AspNetCore.Mvc;
using SharpbinV2.Server.Services;
using SharpbinV2.Server.Models;
using Bcrypt = BCrypt.Net.BCrypt;
using Microsoft.AspNetCore.RateLimiting;

namespace SharpbinV2.Server.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : Controller
    {
        private readonly DatabaseService _databaseService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(DatabaseService databaseService, ILogger<AuthController> logger)
        {
            _databaseService = databaseService;
            _logger = logger;
        }

        [HttpPost("login")]
        [EnableRateLimiting("auth")]
        public async Task<IActionResult> Login([FromBody] AuthRequest request)
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(request.Username) && string.IsNullOrWhiteSpace(request.Email))
                    return BadRequest(new { success = false, message = "Username or Email is required" });
                if (request.Password.Length is < 8 or > 128)
                    return BadRequest(new { success = false, message = "Password must be between 8 and 128 characters" });
                if (!string.IsNullOrWhiteSpace(request.Username) && request.Username.Length > 32)
                    return BadRequest(new { success = false, message = "Username must be 32 characters or less" });
                if (!string.IsNullOrWhiteSpace(request.Email) && request.Email.Length > 128)
                    return BadRequest(new { success = false, message = "Email must be 128 characters or less" });
                if (!string.IsNullOrWhiteSpace(request.Username) && !string.IsNullOrWhiteSpace(request.Email))
                    return BadRequest(new { success = false, message = "Please provide either a username or an email, not both" });

                if (!string.IsNullOrWhiteSpace(requestDetails.Token))
                {
                    var _session = await _databaseService.UserFromToken(requestDetails.Token);
                    if (_session != null)
                    {
                        return BadRequest(new { success = false, message = "You are already logged in" });
                    }
                }

                User? user = null;

                if (!string.IsNullOrWhiteSpace(request.Username))
                    user = await _databaseService.UserFromUsername(request.Username);
                else if (!string.IsNullOrWhiteSpace(request.Email))
                    user = await _databaseService.UserFromEmail(request.Email);

                if (user == null)
                    return Unauthorized(new { success = false, message = "Invalid username or password" });

                if (!Bcrypt.Verify(request.Password, user.Password))
                {
                    return Unauthorized(new { success = false, message = "Invalid username or password" });
                }

                string token = HelperService.GenerateToken();

                var session = await _databaseService.CreateSession(user, requestDetails, token) ?? new Session();
                if (session.UUID == "0" || session == null)
                    return StatusCode(500, new { success = false, message = "Failed to create session" });

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    #if DEBUG
                    Secure = false,
                    #else
                    Secure = true,
                    #endif
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(14)
                };
                Response.Cookies.Append("Authorization", token, cookieOptions);
                return Ok(new
                {
                    success = true,
                    message = "Login successful",
                    token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during login attempt for user {request.Username ?? request.Email}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpPost("register")]
        [EnableRateLimiting("auth")]
        public async Task<IActionResult> Register([FromBody] AuthRequest request)
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(request.Username) && string.IsNullOrWhiteSpace(request.Email))
                    return BadRequest(new { success = false, message = "Username or Email is required" });
                if (request.Password.Length is < 8 or > 128)
                    return BadRequest(new { success = false, message = "Password must be between 8 and 128 characters" });
                if (request.Username.Length is < 3 or > 32)
                    return BadRequest(new { success = false, message = "Username must be between 3 and 32 characters" });
                if (request.Email.Length > 128)
                    return BadRequest(new { success = false, message = "Email must be 128 characters or less" });
                if (!string.IsNullOrWhiteSpace(request.Email) && !HelperService.IsValidEmail(request.Email))
                    return BadRequest(new { success = false, message = "Invalid email" });
                if (!string.IsNullOrWhiteSpace(request.Username) && !string.IsNullOrWhiteSpace(request.Email))
                    return BadRequest(new { success = false, message = "Please provide either a username or an email, not both" });


                if (!string.IsNullOrWhiteSpace(requestDetails.Token))
                {
                    var _session = await _databaseService.UserFromToken(requestDetails.Token);
                    if (_session != null)
                    {
                        return BadRequest(new { success = false, message = "You are already logged in" });
                    }
                }

                if (!string.IsNullOrWhiteSpace(request.Username))
                {
                    var existingUser = await _databaseService.UserFromUsername(request.Username);
                    if (existingUser != null)
                        return BadRequest(new { success = false, message = "Username already exists" });
                }
                else if (!string.IsNullOrWhiteSpace(request.Email))
                {
                    var existingUser = await _databaseService.UserFromEmail(request.Email);
                    if (existingUser != null)
                        return BadRequest(new { success = false, message = "Email already exists" });
                }

                string hashedPassword = Bcrypt.HashPassword(request.Password, Bcrypt.GenerateSalt(12));
                string token = HelperService.GenerateToken();
                string uuid = Guid.NewGuid().ToString();

                User? user = await _databaseService.CreateUser(request.Username, request.Email, hashedPassword, uuid);
                if (user == null)
                    return StatusCode(500, new { success = false, message = "Failed to create user" });

                var session = await _databaseService.CreateSession(user, requestDetails, token) ?? new Session();

                if (session.UUID == "0" || session == null)
                    return StatusCode(500, new { success = false, message = "Failed to create session" });

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    #if DEBUG
                    Secure = false,
                    #else
                    Secure = true,
                    #endif
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddDays(14)
                };

                Response.Cookies.Append("Authorization", token, cookieOptions);
                return Ok(new
                {
                    success = true,
                    message = "Registration successful",
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.Email,
                        user.DisplayName,
                        user.Created
                    },
                    token
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during registration attempt for user {request.Username ?? request.Email}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpGet("authenticated")]
        public async Task<IActionResult> IsAuthenticated()
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(requestDetails.Token))
                {
                    return Unauthorized(new { success = false, message = "Not authenticated, no token found" });
                }
                var user = await _databaseService.UserFromToken(requestDetails.Token);
                if (user == null)
                {
                    return Unauthorized(new { success = false, message = "Not authenticated, invalid token" });
                }
                var session = await _databaseService.GetSession(requestDetails.Token);
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (session == null || session.Expirary < currentTime)
                {
                    Response.Cookies.Delete("Authorization");
                    return Unauthorized(new { success = false, message = "Session expired" });
                }

                return Ok(new
                {
                    success = true,
                    message = "Authenticated",
                    expires = session.Expirary,
                    user = new
                    {
                        user.UID,
                        user.UUID,
                        user.Username,
                        user.Email,
                        user.DisplayName,
                        user.Created,
                        user.LastLogin,
                        user.Type
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking authentication status");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(requestDetails.Token))
                {
                    return Unauthorized(new { success = false, message = "Not authenticated" });
                }
                var user = await _databaseService.UserFromToken(requestDetails.Token);
                if (user == null)
                {
                    return Unauthorized(new { success = false, message = "Not authenticated" });
                }
                await _databaseService.DeleteSession(requestDetails.Token);
                Response.Cookies.Delete("Authorization");
                return Ok(new { success = true, message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout attempt");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> DeleteAccount()
        {
            try
            {
                var requestDetails = HelperService.GetRequestDetails(HttpContext);
                if (string.IsNullOrWhiteSpace(requestDetails.Token))
                {
                    return Unauthorized(new { success = false, message = "Not authenticated" });
                }
                var user = await _databaseService.UserFromToken(requestDetails.Token);
                if (user == null)
                {
                    return Unauthorized(new { success = false, message = "Not authenticated" });
                }
                await _databaseService.DeleteUser(user);
                await _databaseService.DeleteSession(requestDetails.Token);
                Response.Cookies.Delete("Authorization");
                return Ok(new { success = true, message = "Account deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during account deletion attempt");
                return StatusCode(500, "Internal server error");
            }
        }


    }
    public class AuthRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
