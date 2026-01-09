using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;

namespace SharpbinV3.Server.Services
{
    public class PasteCleanUpService(
        IServiceProvider serviceProvider,
        ILogger<PasteCleanUpService> logger
    ) : BackgroundService
    {
        private readonly TimeSpan _period = TimeSpan.FromMinutes(5);

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(_period);
            await Cleanup(stoppingToken);
            while (
                !stoppingToken.IsCancellationRequested
                && await timer.WaitForNextTickAsync(stoppingToken)
            )
            {
                try
                {
                    await Cleanup(stoppingToken);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Error occurred during paste cleanup");
                }
            }
        }

        private async Task Cleanup(CancellationToken stoppingToken)
        {
            using var scope = serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var expiredPastes = db.Pastes.Where(p => p.ExpiresAt != 0 && p.ExpiresAt <= now);
            if (await expiredPastes.AnyAsync(stoppingToken))
            {
                var deletedCount = await expiredPastes.CountAsync(stoppingToken);
                db.Pastes.RemoveRange(expiredPastes);
                await db.SaveChangesAsync(stoppingToken);
                logger.LogInformation("Deleted {Count} expired pastes", deletedCount);
            }
        }
    }
}
