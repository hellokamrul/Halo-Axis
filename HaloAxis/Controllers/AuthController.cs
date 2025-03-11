using HaloAxis.Domain.Contracts;
using HaloAxis.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace HaloAxis.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterAsync([FromBody]UserRegisterRequest request)
        {
            var response = await _userService.RegisterAsync(request);
            return Ok(response);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginAsync([FromBody] UserLoginRequest request)
        {
            var response = await _userService.LoginAsync(request);
            return Ok(response);
        }

        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetByIdAsync(Guid id)
        {
            var response = await _userService.GetByIdAsync(id);
            return Ok(response);
        }

        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] RefreshTokenRequest request)
        {
            var response = await _userService.RefreshTokenAsync(request);
            return Ok(response);
        }

        [HttpPost("revoke-token")]
        [Authorize]
        public async Task<IActionResult> RevokeTokenAsync([FromBody] RefreshTokenRequest request)
        {
            var response = await _userService.RevokeRefreshToken(request);
            if (response != null && response.Message == "Refresh token revoked successfully")
            {
                return Ok(response);
            }

            return BadRequest(response);
        }

        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetUserResponseAsync()
        {
            var response = await _userService.GetCurrentUserAsync();
            return Ok(response);
        }



    }
}
