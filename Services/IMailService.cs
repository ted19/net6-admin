using webAdmin.ViewModels;

namespace webAdmin.Services
{
    public interface IMailService
    {
        Task<bool> SendAsync(MailData mailData, CancellationToken ct);
    }
}