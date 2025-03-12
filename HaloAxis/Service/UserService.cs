using AutoMapper;
using HaloAxis.Domain.Contracts;
using HaloAxis.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace HaloAxis.Service
{
    public class UserService : IUserService
    {
        private readonly ITokenService _tokenService;
        private readonly ICurrentUserService _currentUserService;
        private readonly UserManager<ApplicationUser> _userManager; 
        private readonly IMapper _mapper;
        private readonly ILogger<UserService> _logger;

        public UserService(ITokenService tokenService, ICurrentUserService currentUserService, UserManager<ApplicationUser> userManager, IMapper mapper, ILogger<UserService> logger)
        {
            _tokenService = tokenService;
            _currentUserService = currentUserService;
            _userManager = userManager;
            _mapper = mapper;
            _logger = logger;
        }

        public async Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            _logger.LogInformation("Registering user");
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                _logger.LogError("Email already in use");
                throw new InvalidOperationException("Email already in use");
            }
            var newUser = _mapper.Map<ApplicationUser>(request);

            newUser.UserName = GenerateUserName(request.FirstName, request.LastName);
            var result = await _userManager.CreateAsync(newUser, request.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to create user", errors);
                throw new InvalidOperationException("Failed to create user");
            }

            _logger.LogInformation("User created successfully");
            await _tokenService.GenerateJwtToken(newUser);
            return _mapper.Map<UserResponse>(newUser);

        }

        private string GenerateUserName(string firstName, string lastName)
        {
            var baseUserName = $"{firstName}{lastName}".ToLower();
            var userName = baseUserName;
            var counter = 1;
            while (_userManager.Users.Any(u => u.UserName == userName))
            {
                userName = $"{baseUserName}{counter}";
                counter++;
            }
            return userName;
        }

        public async Task<UserResponse> LoginAsync(UserLoginRequest request)
        {
            if (request == null)
            {
                _logger.LogError("Login request is null");
                throw new ArgumentNullException(nameof(request));
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (user == null || !passwordValid)
            {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }
            //Generate Access Token
            var token =  await _tokenService.GenerateJwtToken(user);

            //Generate Refresh Token
            var refreshToken = _tokenService.GenerateRefreshToken();


            //Save or overwrite Refresh Token to Database 

            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
            user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(2);

            //Update User information in Database
            var result = await _userManager.UpdateAsync(user);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to update user", errors);
                throw new InvalidOperationException("Failed to update user");
            }

            var userResponse = _mapper.Map<ApplicationUser, UserResponse>(user);
            userResponse.AccessToken = token;
            userResponse.RefreshToken = refreshToken;

            return userResponse;


        }

        public async Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }

            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.Email = request.Email;
            user.Gender = request.Gender;




            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Failed to update user", errors);
                throw new InvalidOperationException("Failed to update user");
            }

            return _mapper.Map<UserResponse>(user);
        }
        public async Task DeleteAsync(Guid id)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null) {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }
            await _userManager.DeleteAsync(user);
        }

        public async Task<UserResponse> GetByIdAsync(Guid id)
        {
            _logger.LogInformation("Getting user by id");
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }
            _logger.LogInformation("User found");
            return _mapper.Map<UserResponse>(user);

        }

        public async Task<CurrenUserResponse> GetUserResponseAsync()
        {
            var user = await _userManager.FindByIdAsync(_currentUserService.GetUserId());
            if (user == null) {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }
            return _mapper.Map<CurrenUserResponse>(user);

        }

      

        public async Task<CurrenUserResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("Refreshing token");

            //hash the incoming refresh token and compare it with the one in the database
            using var sha256 = SHA256.Create();
            var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(request.RefreshToken));
            var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

            //find the user based on the refresh token
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
            if (user == null)
            {
                _logger.LogError("User not found");
                throw new InvalidOperationException("User not found");
            }

            //validate the refresh token expiry time
            if (user.RefreshTokenExpiryTime < DateTime.Now)
            {
                _logger.LogWarning("Refresh token expired for user ID:{UserId}",user.Id);
                throw new InvalidOperationException("Refresh token expired");
            }

            //generate new access token
            var newAccessToken = await _tokenService.GenerateJwtToken(user);
            _logger.LogInformation("Token refreshed successfully");
            var currenUserResponse = _mapper.Map<ApplicationUser, CurrenUserResponse>(user);
            currenUserResponse.AccessToken = newAccessToken;
            return currenUserResponse;


        }



        public async Task<RevokeRefreshTokenResponse> RevokeRefreshTokenAsync(RefreshTokenRequest request)
        {
            _logger.LogInformation("Revoking refresh token");

            try
            {
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(request.RefreshToken));
                var hashedRefreshToken = Convert.ToBase64String(refreshTokenHash);

                var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == hashedRefreshToken);
                if (user == null)
                {
                    _logger.LogError("User not found");
                    throw new InvalidOperationException("User not found");
                }

                //validate the refresh token expiry time
                if (user.RefreshTokenExpiryTime < DateTime.Now)
                {
                    _logger.LogWarning("Refresh token expired for user ID:{UserId}", user.Id);
                    throw new InvalidOperationException("Refresh token expired");
                }

                //remove the refresh token from the database
                user.RefreshToken = null;
                user.RefreshTokenExpiryTime = null;

                //update the user in the database
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to update user : {errors}", errors);
                    {
                        return new RevokeRefreshTokenResponse
                        {
                            Message = "Failed to revoke refresh token",
                        };
                        throw new InvalidOperationException("Failed to update user");
                    }
                }
                    _logger.LogInformation("Refresh token revoked successfully");
                    return new RevokeRefreshTokenResponse
                    {
                        Message = "Refresh token revoked successfully",
                    };


                }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, "Failed to revoke refresh token:{ex}");
                throw new InvalidOperationException("Failed to revoke refresh token");
            }
        }

     
    }
}
