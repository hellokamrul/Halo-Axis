using HaloAxis.Domain.Contracts;
using HaloAxis.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace HaloAxis.Service
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        private readonly string? _validIssuer;
        private readonly string? _validAudience;
        private readonly double? _expires;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<TokenService> _logger;

        public TokenService(IConfiguration configuration, UserManager<ApplicationUser> userManager, ILogger<TokenService> logger)
        {
            _userManager = userManager;
            var jwtSettings = configuration.GetSection("Jwt").Get<JwtSettings>();
            if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.Key))
            {
                throw new InvalidOperationException("Jwt secret key is not found");
            }
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));
            _validIssuer = jwtSettings.ValidIssuer;
            _validAudience = jwtSettings.ValidAudience;
            _expires = jwtSettings.Expires;
           // _userManager = userManager;
           // _logger = logger;

        }

        public async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var signingCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
            var claims = await GetClaims(user);
            var token = GenerateTokenOptions(signingCredentials, claims);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<List<Claim>> GetClaims(ApplicationUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user?.UserName ?? string.Empty), 

                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
                new Claim("Gender", user.Gender)
                
            };
            var roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            return claims;
        }

        private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
        {
            return new JwtSecurityToken(
                issuer: _validIssuer,
                audience: _validAudience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(_expires.Value),
                signingCredentials: signingCredentials
            );
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);

            var refreshToken = Convert.ToBase64String(randomNumber);
            return refreshToken;
        }
    }
}
