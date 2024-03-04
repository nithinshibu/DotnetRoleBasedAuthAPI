using DotnetRoleBasedAuthAPI.Core.DTOs;
using DotnetRoleBasedAuthAPI.Core.Entities;
using DotnetRoleBasedAuthAPI.Core.Interfaces;
using DotnetRoleBasedAuthAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DotnetRoleBasedAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            this._authService = authService;
        }

        //Route for seeding roles to Database
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRolesAsync();
            if (seedRoles.IsSucceed)
            {
                return Ok(seedRoles);
            }
            return BadRequest(seedRoles);

        }

        //Route for Registering the users
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDTO)
        {
            var registerResult = await _authService.RegisterAsync(registerDTO);
            if (registerResult.IsSucceed)
            {
                return Ok(registerResult);
            }
            return BadRequest(registerResult);
        }

        //Route --> User Login
        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            var loginResult = await _authService.LoginAsync(loginDTO);
            if (loginResult.IsSucceed)
            {
                return Ok(loginResult);
            }
            return BadRequest(loginResult);
        }



        //Route for making the user as an admin
        [HttpPost]
        [Route("make-admin")]

        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var operationResult = await _authService.MakeAdminAsync(updatePermissionDTO);
            if (operationResult.IsSucceed)
            {
                return Ok(operationResult);
            }
            return BadRequest(operationResult);
        }


        //Route for making the user as an owner
        [HttpPost]
        [Route("make-owner")]

        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var operationResult = await _authService.MakeOwnerAsync(updatePermissionDTO);
            if (operationResult.IsSucceed)
            {
                return Ok(operationResult);
            }
            return BadRequest(operationResult);
        }

    }
}

