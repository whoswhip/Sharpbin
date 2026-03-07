using System.Threading.Channels;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public class EmailService(IOptions<EmailSettings> emailSettings, ILogger<EmailService> logger) : BackgroundService
    {
        private readonly EmailSettings settings = emailSettings.Value;
        private readonly Channel<QueuedEmail> queue = Channel.CreateUnbounded<QueuedEmail>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = false }
        );

        public async Task SendAsync(string to, string subject, string body)
        {
            if (string.IsNullOrWhiteSpace(settings.Host) || string.IsNullOrWhiteSpace(settings.User) || string.IsNullOrWhiteSpace(settings.Password))
            {
                logger.LogWarning($"Email settings are not fully configured. Skipping sending email to {to}");
                return;
            }
            var email = new QueuedEmail(to, subject, body);

            if (queue.Writer.TryWrite(email))
                return;

            await queue.Writer.WriteAsync(email);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var email in queue.Reader.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await SendNowAsync(email, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to send email to {EmailTo}", email.To);
                }
            }
        }

        private async Task SendNowAsync(QueuedEmail email, CancellationToken cancellationToken)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Sharpbin", settings.From));
            message.To.Add(MailboxAddress.Parse(email.To));
            message.Subject = email.Subject;

            message.Body = new TextPart("html") { Text = email.Body };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(settings.Host, settings.Port, SecureSocketOptions.StartTls, cancellationToken);

            await smtp.AuthenticateAsync(settings.User, settings.Password, cancellationToken);

            await smtp.SendAsync(message, cancellationToken);
            await smtp.DisconnectAsync(true, cancellationToken);
        }

        private readonly record struct QueuedEmail(string To, string Subject, string Body);
    }
}
