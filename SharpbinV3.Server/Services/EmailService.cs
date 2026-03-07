using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using SharpbinV3.Server.Settings;

namespace SharpbinV3.Server.Services
{
    public class EmailService(IOptions<EmailSettings> emailSettings)
    {
        private readonly EmailSettings settings = emailSettings.Value;

        public async Task SendAsync(string to, string subject, string body)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("Sharpbin", settings.From));
            message.To.Add(MailboxAddress.Parse(to));
            message.Subject = subject;

            message.Body = new TextPart("html") { Text = body };

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(settings.Host, settings.Port, SecureSocketOptions.StartTls);

            await smtp.AuthenticateAsync(settings.User, settings.Password);

            await smtp.SendAsync(message);
            await smtp.DisconnectAsync(true);
        }
    }
}
