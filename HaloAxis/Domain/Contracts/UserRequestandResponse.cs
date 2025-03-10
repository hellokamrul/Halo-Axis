namespace HaloAxis.Domain.Contracts
{
    public class UserRegisterRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Gender { get; set; }
    }

    public class UserResponse
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Gender { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }

    public class UserLoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class CurrenUserResponse
    {
        //public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Gender { get; set; }
        public string AccessToken { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
    }

    public class UpdateUserRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Gender { get; set; }
    }

    public class RevokeRefreshTokenResponse
    {
        public string Token { get; set; }

    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }


}   