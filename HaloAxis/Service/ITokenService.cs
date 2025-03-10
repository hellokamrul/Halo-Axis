using HaloAxis.Domain.Entities;

namespace HaloAxis.Service
{
    public interface ITokenService
    {
        Task<string> GenerateJwtToken(ApplicationUser user);
        string GenerateRefreshToken();
    }
}
