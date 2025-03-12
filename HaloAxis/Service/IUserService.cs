using HaloAxis.Domain.Contracts;

namespace HaloAxis.Service
{
    public interface IUserService
    {
        Task<UserResponse> RegisterAsync(UserRegisterRequest request);
        Task<CurrenUserResponse> GetUserResponseAsync();
        Task<UserResponse> GetByIdAsync(Guid id);
        Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request);
        Task DeleteAsync(Guid id);
        Task<UserResponse> LoginAsync(UserLoginRequest request);
        Task<RevokeRefreshTokenResponse> RevokeRefreshTokenAsync(RefreshTokenRequest request);
        Task<CurrenUserResponse> RefreshTokenAsync(RefreshTokenRequest request);

    }
}
