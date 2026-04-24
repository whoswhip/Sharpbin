using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.DTOs.Paste;
using SharpbinV3.Server.DTOs.Report;
using SharpbinV3.Server.DTOs.User;
using SharpbinV3.Server.Extensions;
using SharpbinV3.Server.Services;
using SharpbinV3.Server.Services.Verification;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasteController(
        PasteService pasteService,
        CommentService commentService,
        VerificationService verificationService,
        AuthService authService,
        ReportService reportService,
        ICompressionService compressionService,
        IOptions<PasteSettings> options,
        IOptions<AuthSettings> authSettings
    ) : ControllerBase
    {
        private readonly PasteService _pasteService = pasteService;
        private readonly CommentService _commentService = commentService;
        private readonly VerificationService _verificationService = verificationService;
        private readonly AuthService _authService = authService;
        private readonly ReportService _reportService = reportService;
        private readonly ICompressionService _compressionService = compressionService;
        private readonly PasteSettings _pasteSettings = options.Value;
        private readonly AuthSettings _authSettings = authSettings.Value;

        [HttpPost]
        [Route("create")]
        [Authorize(Policy = "NotBanned")]
        [EnableRateLimiting("Strict")]
        public async Task<IActionResult> CreatePaste(
            string title = "",
            string syntax = "plaintext",
            Visibility visibility = Visibility.Public,
            long expiresAt = 0,
            string? verificationToken = null
        )
        {
            if (!_pasteService.ValidateExpiresAt(expiresAt))
                return BadRequest(new { success = false, message = "Invalid expiration time." });
            if (!_pasteService.ValidateVisibility(visibility))
                return BadRequest(new { success = false, message = "Invalid visibility level. Must be between 0 and 2." });
            if (!_pasteService.ValidateSyntax(syntax))
                return BadRequest(new { success = false, message = "Invalid syntax." });
            if (!_pasteService.ValidateTitle(title))
                return BadRequest(new { success = false, message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content.Length == 0)
                return BadRequest(new { success = false, message = "Paste content cannot be empty." });
            if (System.Text.Encoding.UTF8.GetByteCount(content) > _pasteSettings.MaxPasteSizeInBytes)
                return BadRequest(
                    new { success = false, message = $"Paste size exceeds the maximum allowed size of {_pasteSettings.MaxPasteSizeInBytes} bytes." }
                );

            if (_pasteSettings.RequiresVerification && !HttpContext.IsApiKeyAuthenticated())
            {
                var providedApiKey = HttpContext.GetApiKey();
                if (providedApiKey != null)
                    return BadRequest(new { success = false, message = "Invalid API key." });

                var verifyResult = await _verificationService.VerifyAsync(
                    new VerificationContext { Token = verificationToken, Ip = HttpContext.GetRequestIP() }
                );
                if (!verifyResult)
                    return BadRequest(new { success = false, message = "Verification failed." });
            }

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            Paste paste = await _pasteService.Create(user, content, title, syntax, visibility, expiresAt, _pasteSettings.EnablePasteCompression);
            return Ok(
                new PasteCreatedResponseDto
                {
                    ID = paste.ID,
                    UUID = paste.UUID,
                    CreatedAt = paste.CreatedAt,
                    IsCompressed = paste.IsCompressed,
                    StoredSize = paste.StoredSize,
                    OriginalSize = paste.OriginalSize,
                    ExpiresAt = paste.ExpiresAt,
                    Visibility = paste.Visibility,
                }
            );
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("{id}")]
        public async Task<IActionResult> GetPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            var jwtUser = HttpContext.GetJwtUser();
            PasteInteraction? userInteraction = null;
            if (jwtUser != null)
                userInteraction = await _pasteService.GetUserInteraction(paste, jwtUser.UUID);

            int? reportCount = null;
            if (jwtUser != null && (jwtUser.Roles.HasFlag(Role.Admin) || jwtUser.Roles.HasFlag(Role.Moderator)))
            {
                var query = new ReportQuery { PastePID = paste.PID };
                reportCount = await _reportService.GetReportCount(query);
            }

            return Ok(
                new
                {
                    success = true,
                    paste = new PasteResponseDto
                    {
                        ID = paste.ID,
                        UUID = paste.UUID,
                        CreatedAt = paste.CreatedAt,
                        Title = paste.Title,
                        StoredSize = paste.StoredSize,
                        OriginalSize = paste.OriginalSize,
                        IsCompressed = paste.IsCompressed,
                        Views = paste.Views,
                        Syntax = paste.Syntax,
                        Visibility = paste.Visibility,
                        ExpiresAt = paste.ExpiresAt,
                        EditedAt = paste.EditedAt,
                        ReportCount = reportCount,
                        UserReaction = userInteraction != null ? userInteraction.Type : null,
                        Likes = paste.PositiveInteractionCount,
                        Dislikes = paste.NegativeInteractionCount,
                        Author =
                            paste.User != null && paste.User.Visibility == 0
                                ? new UserSimpleDto
                                {
                                    UID = paste.User.UID,
                                    UUID = paste.User.UUID,
                                    Username = paste.User.Username,
                                    DisplayName = paste.User.DisplayName,
                                    Visibility = paste.User.Visibility,
                                    Roles = paste.User.Roles,
                                    IsBanned = paste.User.IsBanned,
                                }
                                : null,
                    },
                }
            );
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("{id}/raw")]
        public async Task<IActionResult> GetRawPasteByID(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound();
            if (paste.IsCompressed)
                Response.Headers.Append("Content-Encoding", "gzip");

            return File(paste.Content, "text/plain; charset=utf-8");
        }

        [HttpPut]
        [Route("{id}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> EditPaste(string id)
        {
            string content = await new StreamReader(Request.Body).ReadToEndAsync();
            if (content == null || id == null)
                return StatusCode(400, new { success = false, message = "Invalid request." });

            var paste = await _pasteService.Get(id);
            if (paste == null)
                return StatusCode(404, new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser()!;

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to edit this paste." });

            bool result = await _pasteService.EditText(paste, content);
            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while editing the paste." });
            return Ok(new { message = "Paste edited successfully." });
        }

        [HttpPatch]
        [Route("{id}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> ModifyPasteMetadata(string id, [FromBody] UpdatePasteDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser()!;

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);

            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to modify this paste." });

            if (request.Title != null)
                paste.Title = request.Title;
            if (request.Syntax != null)
                paste.Syntax = request.Syntax;
            if (request.Visibility.HasValue)
                paste.Visibility = request.Visibility.Value;
            if (request.ExpiresAt.HasValue)
                paste.ExpiresAt = request.ExpiresAt.Value;

            if (!_pasteService.ValidateExpiresAt(paste.ExpiresAt))
                return BadRequest(new { success = false, message = "Invalid expiration time." });
            if (!_pasteService.ValidateVisibility(paste.Visibility))
                return BadRequest(new { success = false, message = "Invalid visibility level. Must be between 0 and 2." });
            if (!_pasteService.ValidateSyntax(paste.Syntax ?? "plaintext"))
                return BadRequest(new { success = false, message = "Invalid syntax." });
            if (!_pasteService.ValidateTitle(paste.Title ?? ""))
                return BadRequest(new { success = false, message = $"Invalid title. Must be less than {_pasteSettings.MaxTitleLength} characters." });

            var newPaste = await _pasteService.Edit(paste);
            return Ok(
                new
                {
                    success = true,
                    message = "Paste metadata updated successfully.",
                    paste = new PasteResponseDto
                    {
                        ID = newPaste.ID,
                        UUID = newPaste.UUID,
                        CreatedAt = newPaste.CreatedAt,
                        Title = newPaste.Title,
                        OriginalSize = newPaste.OriginalSize,
                        StoredSize = newPaste.StoredSize,
                        IsCompressed = newPaste.IsCompressed,
                        Views = newPaste.Views,
                        Syntax = newPaste.Syntax,
                        Visibility = newPaste.Visibility,
                        ExpiresAt = newPaste.ExpiresAt,
                    },
                }
            );
        }

        [HttpDelete]
        [Route("{id}")]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        public async Task<IActionResult> DeletePaste(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            var user = HttpContext.GetJwtUser()!;

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (paste.AuthorUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this paste." });

            bool result = await _pasteService.Delete(paste);
            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while deleting the paste." });
            return Ok(new { success = true, message = "Paste deleted successfully." });
        }

        [HttpPost]
        [Route("{id}/view")]
        [Authorize(Policy = "NotBanned")]
        public async Task<IActionResult> RecordPasteView(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null)
                return NotFound(new { success = false, message = "Paste not found." });

            if (_pasteSettings.View_HMAC_Secret == null)
                return StatusCode(500, new { success = false, message = "View recording is not configured properly." });
            if (
                !string.IsNullOrWhiteSpace(_pasteSettings.View_Internal_API_Key)
                && _pasteSettings.View_Internal_API_Key != Request.Headers["X-Internal-API-Key"]
            )
                return Unauthorized(new { success = false, message = "Invalid API key." });

            if (paste.AuthorUUID != HttpContext.GetJwtUser()?.UUID)
                return Ok(new { success = true, message = "View not recorded for author's own paste." });
            if (paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() && paste.Visibility != 0)
                return Ok(new { success = true, message = "View not recorded for expired paste." });

            var result = await _pasteService.RecordView(paste, HttpContext);

            if (result.paste is null && !result.alreadyExists)
                return StatusCode(500, new { success = false, message = "An error occurred while recording the paste view." });
            else if (result.alreadyExists)
                return Ok(new { success = true, message = "View already recorded." });

            return Ok(new { success = true, message = "Paste view recorded." });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [Route("{id}/reaction")]
        public async Task<IActionResult> ReactToPaste(string id, [FromBody] ReactToPasteDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return Unauthorized(new { success = false, message = "User not authenticated." });
            if (paste.AuthorUUID == user.UUID)
                return BadRequest(new { success = false, message = "You cannot react to your own paste." });

            var existingInteraction = await _pasteService.GetUserInteraction(paste, user.UUID);

            if (request.Reaction.HasValue)
            {
                if (existingInteraction == null)
                {
                    var created = await _pasteService.RecordInteraction(paste, user, request.Reaction.Value);
                    if (created == null)
                        return StatusCode(500, new { success = false, message = "Could not save reaction." });
                }
                else if (existingInteraction.Type != request.Reaction.Value)
                {
                    var removed = await _pasteService.RemoveInteraction(paste, user);
                    if (!removed)
                        return StatusCode(500, new { success = false, message = "Could not update reaction." });

                    var created = await _pasteService.RecordInteraction(paste, user, request.Reaction.Value);
                    if (created == null)
                        return StatusCode(500, new { success = false, message = "Could not update reaction." });
                }
            }
            else if (existingInteraction != null)
            {
                var removed = await _pasteService.RemoveInteraction(paste, user);
                if (!removed)
                    return StatusCode(500, new { success = false, message = "Could not remove reaction." });
            }

            var updatedPaste = await _pasteService.Get(id);
            if (updatedPaste == null)
                return StatusCode(500, new { success = false, message = "Could not load updated paste." });

            var updatedInteraction = await _pasteService.GetUserInteraction(updatedPaste, user.UUID);

            return Ok(
                new
                {
                    success = true,
                    reaction = new PasteReactionResponseDto
                    {
                        PasteID = updatedPaste.ID,
                        Likes = updatedPaste.PositiveInteractionCount,
                        Dislikes = updatedPaste.NegativeInteractionCount,
                        UserReaction = updatedInteraction?.Type,
                    },
                }
            );
        }

        [HttpGet]
        [Route("recent")]
        public async Task<IActionResult> GetRecentPastes()
        {
            var results = await _pasteService.GetList(0, 50, true);
            return Ok(
                results.Select(p => new PasteResponseDto
                {
                    ID = p.ID,
                    UUID = p.UUID,
                    CreatedAt = p.CreatedAt,
                    Title = p.Title,
                    StoredSize = p.StoredSize,
                    OriginalSize = p.OriginalSize,
                    IsCompressed = p.IsCompressed,
                    Views = p.Views,
                    Syntax = p.Syntax,
                    Visibility = p.Visibility,
                    ExpiresAt = p.ExpiresAt,
                    EditedAt = p.EditedAt,
                    Author =
                        p.User != null && p.User.Visibility == 0
                            ? new UserSimpleDto
                            {
                                UID = p.User.UID,
                                UUID = p.User.UUID,
                                Username = p.User.Username,
                                DisplayName = p.User.DisplayName,
                                Visibility = p.User.Visibility,
                                Roles = p.User.Roles,
                                IsBanned = p.User.IsBanned,
                            }
                            : null,
                })
            );
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("{id}/comments")]
        public async Task<IActionResult> GetComments(string id)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            var comments = await _commentService.GetCommentsByPaste(paste);

            Dictionary<long, Interaction>? userInteractionMap = null;
            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user != null)
                userInteractionMap = await _commentService.GetUserInteractions(comments.Select(c => c.Id).ToList(), user.UUID);

            return Ok(new { success = true, comments = comments.Select(c => ToCommentResponse(c, userInteractionMap)) });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [Route("{id}/comments")]
        public async Task<IActionResult> CreateComment(string id, [FromBody] CreateCommentDto request)
        {
            if (string.IsNullOrWhiteSpace(request.Content))
                return BadRequest(new { success = false, message = "Comment content cannot be empty." });

            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            if (Encoding.UTF8.GetByteCount(request.Content) > 5000)
                return BadRequest(new { success = false, message = "Comment content exceeds maximum size of 5000 bytes." });

            if (request.ParentCommentID.HasValue)
            {
                var parent = await _commentService.GetCommentByID(request.ParentCommentID.Value, paste.PID);
                if (parent == null)
                    return BadRequest(new { success = false, message = "Parent comment not found for this paste." });
            }

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return Unauthorized(new { success = false, message = "User not authenticated." });

            var comment = await _commentService.CreateComment(user, paste, request.Content, request.ParentCommentID);
            var created = await _commentService.GetCommentByID(comment.Id);
            if (created == null)
                return StatusCode(500, new { success = false, message = "Failed to load created comment." });

            var userInteractionMap = new Dictionary<long, Interaction>();
            return Ok(new { success = true, comment = ToCommentResponse(created, userInteractionMap) });
        }

        [HttpPost]
        [Authorize(Policy = "JwtOnlyAndNotBanned")]
        [Route("{id}/comments/{commentId}/reaction")]
        public async Task<IActionResult> ReactToComment(string id, long commentId, [FromBody] ReactToCommentDto request)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            var comment = await _commentService.GetCommentByID(commentId, paste.PID);
            if (comment == null)
                return NotFound(new { success = false, message = "Comment not found for this paste." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return Unauthorized(new { success = false, message = "User not authenticated." });

            if (request.Reaction.HasValue)
            {
                var result = await _commentService.UpsertInteraction(comment, user, request.Reaction.Value);
                if (result == null)
                    return StatusCode(500, new { success = false, message = "Could not save reaction." });
            }
            else
            {
                await _commentService.RemoveInteraction(comment, user);
            }

            var updated = await _commentService.GetCommentByID(commentId);
            if (updated == null)
                return StatusCode(500, new { success = false, message = "Could not load updated comment." });

            var interactionMap = await _commentService.GetUserInteractions([commentId], user.UUID);
            Interaction? userReaction = null;
            if (interactionMap.TryGetValue(commentId, out var mappedReaction))
                userReaction = mappedReaction;

            return Ok(
                new
                {
                    success = true,
                    reaction = new CommentReactionResponseDto
                    {
                        CommentID = updated.Id,
                        Likes = updated.PositiveInteractionCount,
                        Dislikes = updated.NegativeInteractionCount,
                        UserReaction = userReaction,
                    },
                }
            );
        }

        [HttpDelete]
        [Authorize(Policy = "JwtOnly")]
        [Route("{id}/comments/{commentId}")]
        public async Task<IActionResult> DeleteComment(string id, long commentId, bool hardDelete = false)
        {
            var paste = await _pasteService.Get(id);
            if (paste == null || paste.ExpiresAt != 0 && paste.ExpiresAt < DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                return NotFound(new { success = false, message = "Paste not found" });

            var comment = await _commentService.GetCommentByID(commentId, paste.PID);
            if (comment == null)
                return NotFound(new { success = false, message = "Comment not found for this paste." });

            var user = await _authService.GetUserFromHttpContext(HttpContext);
            if (user == null)
                return Unauthorized(new { success = false, message = "User not authenticated." });

            var hasPrivilegedRole = user.Roles.HasFlag(Role.Admin) || user.Roles.HasFlag(Role.Moderator);
            if (comment.UserUUID != user.UUID && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to delete this comment." });
            if (hardDelete && !hasPrivilegedRole)
                return StatusCode(403, new { success = false, message = "You do not have permission to hard delete this comment." });

            bool result;
            if (hardDelete)
                result = await _commentService.HardDeleteComment(comment);
            else
                result = await _commentService.DeleteComment(comment);

            if (!result)
                return StatusCode(500, new { success = false, message = "An error occurred while deleting the comment." });
            return Ok(new { success = true, message = "Comment deleted successfully." });
        }

        [HttpGet]
        [EnableRateLimiting("NoLimit")]
        [Route("info")]
        public IActionResult GetCreatePasteOptions()
        {
            return Ok(
                new PasteOptionsDto
                {
                    Syntaxes = [.. _pasteSettings.ValidSyntaxLanguages],
                    Visibilities =
                    [
                        new() { Value = 0, DisplayName = "Public" },
                        new() { Value = 1, DisplayName = "Unlisted" },
                        new() { Value = 2, DisplayName = "Private" },
                    ],
                    MaxTitleLength = _pasteSettings.MaxTitleLength,
                    MaxPasteSize = _pasteSettings.MaxPasteSizeInBytes,
                    RequiresVerification = _pasteSettings.RequiresVerification,
                }
            );
        }

        private CommentResponseDto ToCommentResponse(Comment comment, Dictionary<long, Interaction>? userInteractionMap)
        {
            string? content = null;
            if (comment.Content != null)
            {
                var bytes = comment.IsCompressed ? _compressionService.Decompress(comment.Content) : comment.Content;
                content = Encoding.UTF8.GetString(bytes);
            }

            Interaction? userReaction = null;
            if (userInteractionMap != null && userInteractionMap.TryGetValue(comment.Id, out var mappedReaction))
                userReaction = mappedReaction;

            return new CommentResponseDto
            {
                Id = comment.Id,
                ParentCommentID = comment.ParentCommentID,
                Content = content,
                StoredSize = comment.StoredSize,
                OriginalSize = comment.OriginalSize,
                IsCompressed = comment.IsCompressed,
                CreatedAt = comment.CreatedAt,
                UpdatedAt = comment.UpdatedAt,
                Likes = comment.PositiveInteractionCount,
                Dislikes = comment.NegativeInteractionCount,
                UserReaction = userReaction,
                Author =
                    comment.User != null && comment.User.Visibility == 0
                        ? new UserSimpleDto
                        {
                            UID = comment.User.UID,
                            UUID = comment.User.UUID,
                            Username = comment.User.Username,
                            DisplayName = comment.User.DisplayName,
                            Visibility = comment.User.Visibility,
                            Roles = comment.User.Roles,
                            IsBanned = comment.User.IsBanned,
                        }
                        : null,
            };
        }
    }
}
