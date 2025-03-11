using HaloAxis.Domain.Contracts;

namespace HaloAxis.Service
{
    public interface IUserService
    {
        Task<UserResponse> RegisterAsync(UserRegisterRequest request);
        Task<CurrenUserResponse> GetCurrentUserAsync();
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest);
        Task<CurrenUserResponse> RefreshTokenAsync(RefreshTokenRequest request);

        Task<UserResponse> LoginAsync(UserLoginRequest request);

    }
}
