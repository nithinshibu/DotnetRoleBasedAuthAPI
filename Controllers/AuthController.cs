using DotnetRoleBasedAuthAPI.Core.DTOs;
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
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //Route for seeding roles to Database
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {

            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if(isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                return Ok("Roles Seeding is Already Done!");
            }

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));

            return Ok("Role Seeding Completed");
        }

        //Route for Registering the users
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDTO)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDTO.UserName);
            if(isExistsUser != null)
            {
                return BadRequest("Username already exists");
            }
            IdentityUser newUser = new IdentityUser()
            {
                Email = registerDTO.Email,
                UserName = registerDTO.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            //Creating the new user
            var createUserResult = await _userManager.CreateAsync(newUser,registerDTO.Password);
            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed because: ";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return BadRequest(errorString);
            }
            //Add a default user role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("User Created Successfully");
        }

        //Route --> User Login
        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            var user = await _userManager.FindByNameAsync(loginDTO.UserName);
            //For security reasons, we are not providing any detailed reason, instead throwing unauthorized error
            if(user is null)
            {
                return Unauthorized("Invalid Credentials");
            }

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDTO.Password);

            if (!isPasswordCorrect)
            {
                return Unauthorized("Invalid Credentials");
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            //Creating claims

            var authClaims = new List<Claim>
            {
                 new Claim(ClaimTypes.Name,user.UserName),
                 new Claim(ClaimTypes.NameIdentifier,user.Id),
                 new Claim("JWTID",Guid.NewGuid().ToString() ),
            };

            foreach(var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role,userRole));
            }

            var token = GenerateJWTAccessToken(authClaims);

            return Ok(token);
        }

        private string GenerateJWTAccessToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(issuer: _configuration["JWT:ValidIssuer"],audience: _configuration["JWT:ValidAudience"],expires:DateTime.Now.AddHours(1),claims:authClaims,signingCredentials: new SigningCredentials(authSecret,SecurityAlgorithms.HmacSha256));

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;

        }

        //Route for making the user as an admin
        [HttpPost]
        [Route("make-admin")]

        public async Task<IActionResult> MakeAdmin([FromBody]UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
            if (user is null)
            {
                return BadRequest("Invalid User Name !!!");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return Ok("User is now an ADMIN");
        }


        //Route for making the user as an owner
        [HttpPost]
        [Route("make-owner")]

        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDTO updatePermissionDTO)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
            if (user is null)
            {
                return BadRequest("Invalid User Name !!!");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return Ok("User is now an OWNER");
        }

    }
}

