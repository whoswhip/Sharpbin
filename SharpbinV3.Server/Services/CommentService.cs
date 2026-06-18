using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SharpbinV3.Server.Data;
using SharpbinV3.Server.Data.Entities;
using SharpbinV3.Server.Data.Enums;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public class CommentService(AppDbContext dbContext, ICompressionService cs, IOptions<PasteSettings> options)
    {
        private readonly AppDbContext _db = dbContext;
        private readonly ICompressionService _cs = cs;
        private readonly PasteSettings _pasteSettings = options.Value;

        public async Task<Comment> CreateComment(User author, Paste paste, string content, long? parentCommentId)
        {
            long originalSize = Encoding.UTF8.GetByteCount(content);
            var data = Encoding.UTF8.GetBytes(content);
            if (_pasteSettings.EnablePasteCompression)
                data = _cs.Compress(content);

            double compressionRatio = (double)data.Length / originalSize;
            var isCompressed = compressionRatio < _pasteSettings.CompressionThreshold;
            var storedContent = isCompressed ? data : Encoding.UTF8.GetBytes(content);

            var comment = new Comment
            {
                PastePID = paste.PID,
                ParentCommentID = parentCommentId,
                Content = storedContent,
                StoredSize = storedContent.Length,
                OriginalSize = originalSize,
                IsCompressed = isCompressed,
                UserUUID = author.UUID,
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };

            _db.Comments.Add(comment);
            author.Comments.Add(comment);
            paste.Comments.Add(comment);
            await _db.SaveChangesAsync();

            return comment;
        }

        public async Task<bool> EditComment(Comment comment, string newContent)
        {
            long originalSize = Encoding.UTF8.GetByteCount(newContent);
            var data = Encoding.UTF8.GetBytes(newContent);
            if (_pasteSettings.EnablePasteCompression)
                data = _cs.Compress(newContent);

            double compressionRatio = (double)data.Length / originalSize;
            var isCompressed = compressionRatio < _pasteSettings.CompressionThreshold;
            var storedContent = isCompressed ? data : Encoding.UTF8.GetBytes(newContent);

            comment.Content = storedContent;
            comment.StoredSize = storedContent.Length;
            comment.OriginalSize = originalSize;
            comment.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            comment.IsCompressed = isCompressed;

            _db.Comments.Update(comment);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }

        public async Task<bool> DeleteComment(Comment comment)
        {
            comment.Content = null;
            comment.StoredSize = 0;
            comment.OriginalSize = 0;
            comment.IsCompressed = false;
            comment.UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            _db.Comments.Update(comment);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }

        public async Task<bool> HardDeleteComment(Comment comment)
        {
            var commentIdsToDelete = new HashSet<long> { comment.Id };
            var currentLevelIds = new List<long> { comment.Id };

            while (currentLevelIds.Count != 0)
            {
                var childIds = await _db
                    .Comments.Where(c => c.ParentCommentID.HasValue && currentLevelIds.Contains(c.ParentCommentID.Value))
                    .Select(c => c.Id)
                    .ToListAsync();

                currentLevelIds = [];
                foreach (var childId in childIds)
                {
                    if (commentIdsToDelete.Add(childId))
                        currentLevelIds.Add(childId);
                }
            }

            var commentsToDelete = await _db.Comments.Where(c => commentIdsToDelete.Contains(c.Id)).ToListAsync();
            _db.Comments.RemoveRange(commentsToDelete);
            var result = await _db.SaveChangesAsync();
            return result > 0;
        }

        public async Task<Comment?> GetCommentByID(long commentID)
        {
            var comment = await _db.Comments.Include(c => c.User).Include(c => c.Paste).FirstOrDefaultAsync(c => c.Id == commentID);
            if (comment == null)
                return null;

            comment.PositiveInteractionCount = await _db.CommentInteractions.CountAsync(ci =>
                ci.CommentID == commentID && ci.Type == Interaction.Positive
            );
            comment.NegativeInteractionCount = await _db.CommentInteractions.CountAsync(ci =>
                ci.CommentID == commentID && ci.Type == Interaction.Negative
            );

            return comment;
        }

        public async Task<Comment?> GetCommentByID(long commentID, long pastePID)
        {
            var comment = await _db
                .Comments.Include(c => c.User)
                .Include(c => c.Paste)
                .FirstOrDefaultAsync(c => c.Id == commentID && c.PastePID == pastePID);
            if (comment == null)
                return null;

            comment.PositiveInteractionCount = await _db.CommentInteractions.CountAsync(ci =>
                ci.CommentID == commentID && ci.Type == Interaction.Positive
            );
            comment.NegativeInteractionCount = await _db.CommentInteractions.CountAsync(ci =>
                ci.CommentID == commentID && ci.Type == Interaction.Negative
            );

            return comment;
        }

        public async Task<List<Comment>> GetCommentsByPaste(Paste paste)
        {
            var comments = await _db.Comments.Where(c => c.PastePID == paste.PID).Include(c => c.User).ToListAsync();
            await PopulateInteractionCounts(comments);
            return comments;
        }

        public async Task<List<Comment>> GetCommentsByUser(User user)
        {
            var comments = await _db.Comments.Where(c => c.UserUUID == user.UUID).Include(c => c.Paste).ToListAsync();
            await PopulateInteractionCounts(comments);
            return comments;
        }

        public async Task<List<Comment>> GetReplies(Comment parentComment)
        {
            var comments = await _db.Comments.Where(c => c.ParentCommentID == parentComment.Id).Include(c => c.User).ToListAsync();
            await PopulateInteractionCounts(comments);
            return comments;
        }

        public async Task<Dictionary<long, Interaction>> GetUserInteractions(List<long> commentIds, Guid userUUID)
        {
            if (commentIds.Count == 0)
                return [];

            return await _db
                .CommentInteractions.Where(ci => commentIds.Contains(ci.CommentID) && ci.UserUUID == userUUID)
                .ToDictionaryAsync(ci => ci.CommentID, ci => ci.Type);
        }

        public async Task<CommentInteraction?> UpsertInteraction(Comment comment, User user, Interaction type)
        {
            var interaction = await _db.CommentInteractions.FirstOrDefaultAsync(ci => ci.CommentID == comment.Id && ci.UserUUID == user.UUID);

            if (interaction == null)
            {
                interaction = new CommentInteraction
                {
                    CommentID = comment.Id,
                    UserUUID = user.UUID,
                    Type = type,
                };

                _db.CommentInteractions.Add(interaction);
            }
            else
            {
                interaction.Type = type;
                _db.CommentInteractions.Update(interaction);
            }

            try
            {
                await _db.SaveChangesAsync();
                return interaction;
            }
            catch (DbUpdateException)
            {
                return null;
            }
        }

        public async Task<bool> RemoveInteraction(Comment comment, User user)
        {
            var interaction = await _db.CommentInteractions.FirstOrDefaultAsync(ci => ci.CommentID == comment.Id && ci.UserUUID == user.UUID);
            if (interaction == null)
                return false;

            _db.CommentInteractions.Remove(interaction);
            await _db.SaveChangesAsync();
            return true;
        }

        private async Task PopulateInteractionCounts(List<Comment> comments)
        {
            if (comments.Count == 0)
                return;

            var commentIds = comments.Select(c => c.Id).ToList();
            var groupedCounts = await _db
                .CommentInteractions.Where(ci => commentIds.Contains(ci.CommentID))
                .GroupBy(ci => new { ci.CommentID, ci.Type })
                .Select(g => new
                {
                    g.Key.CommentID,
                    g.Key.Type,
                    Count = g.Count(),
                })
                .ToListAsync();

            var positiveCounts = groupedCounts.Where(c => c.Type == Interaction.Positive).ToDictionary(c => c.CommentID, c => c.Count);
            var negativeCounts = groupedCounts.Where(c => c.Type == Interaction.Negative).ToDictionary(c => c.CommentID, c => c.Count);

            foreach (var comment in comments)
            {
                comment.PositiveInteractionCount = positiveCounts.GetValueOrDefault(comment.Id, 0);
                comment.NegativeInteractionCount = negativeCounts.GetValueOrDefault(comment.Id, 0);
            }
        }
    }
}
