using Microsoft.EntityFrameworkCore;
using SharpbinV3.Server.Data;

namespace SharpbinV3.Server.Services
{
    public sealed class PasteViewCleanUpService(
        IServiceProvider serviceProvider,
        ILogger<PasteViewCleanUpService> logger
    ) : BackgroundService
    {
        private static readonly TimeSpan Period = TimeSpan.FromHours(1);
        private static readonly long RetentionMs =
            (long)TimeSpan.FromDays(7).TotalMilliseconds;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(Period);

            while (!stoppingToken.IsCancellationRequested &&
                   await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await Cleanup(stoppingToken);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "PasteView cleanup failed");
                }
            }
        }

        private async Task Cleanup(CancellationToken token)
        {
            using var scope = serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var cutoff =
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - RetentionMs;

            var deleted = await db.PasteViews
                .Where(v => v.ViewedAt < cutoff)
                .ExecuteDeleteAsync(token);

            if (deleted > 0)
                logger.LogInformation("Deleted {Count} stale paste views", deleted);
        }
    }

}