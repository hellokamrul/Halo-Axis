using HaloAxis.Domain.Entities;

namespace HaloAxis.Service
{
    public class TokenService : ITokenService
    {
        public Task<string> GenerateJwtToken(ApplicationUser user)
        {
            throw new NotImplementedException();
        }

        public string GenerateRefreshToken()
        {
            throw new NotImplementedException();
        }
    }
}
