using DotnetRoleBasedAuthAPI.Core.DTOs;
using DotnetRoleBasedAuthAPI.Core.Entities;
using DotnetRoleBasedAuthAPI.Core.Interfaces;
using DotnetRoleBasedAuthAPI.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DotnetRoleBasedAuthAPI.Core.Services
{
    public class AuthService : IAuthService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        public async Task<AuthServiceResponseDTO> LoginAsync(LoginDTO loginDTO)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(loginDTO.UserName);
                //For security reasons, we are not providing any detailed reason, instead throwing unauthorized error
                if (user is null)
                {
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = "Invalid Credentials" };
                }

                var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDTO.Password);

                if (!isPasswordCorrect)
                {
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = "Invalid Credentials" };
                }

                var userRoles = await _userManager.GetRolesAsync(user);

                //Creating claims

                var authClaims = new List<Claim>
            {
                 new Claim(ClaimTypes.Name,user.UserName),
                 new Claim(ClaimTypes.NameIdentifier,user.Id),
                 new Claim("JWTID",Guid.NewGuid().ToString() ),
                 new Claim("FirstName", user.FirstName),
                 new Claim("LastName", user.LastName)
            };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = GenerateJWTAccessToken(authClaims);

                return new AuthServiceResponseDTO() { IsSucceed = true, Message = token };

            }
            catch (Exception ex)
            {
                return new AuthServiceResponseDTO() { IsSucceed = false, Message = ex.Message };
            }
        }

        public async Task<AuthServiceResponseDTO> MakeAdminAsync(UpdatePermissionDTO updatePermissionDTO)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
                if (user is null)
                {
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = "Invalid User Name !!!" };
                }

                await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
                return new AuthServiceResponseDTO() { IsSucceed = true, Message = "User is now an ADMIN" };
            }
            catch (Exception ex)
            {
                return new AuthServiceResponseDTO() { IsSucceed = false, Message = ex.Message };
            }
        }

        public async Task<AuthServiceResponseDTO> MakeOwnerAsync(UpdatePermissionDTO updatePermissionDTO)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(updatePermissionDTO.UserName);
                if (user is null)
                {
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = "Invalid User Name !!!" };
                }

                await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
                return new AuthServiceResponseDTO() { IsSucceed = true, Message = "User is now an OWNER" };
            }
            catch (Exception ex)
            {
                return new AuthServiceResponseDTO() { IsSucceed = false, Message = ex.Message };
            }
        }

        public async Task<AuthServiceResponseDTO> RegisterAsync(RegisterDTO registerDTO)
        {
            try
            {
                var isExistsUser = await _userManager.FindByNameAsync(registerDTO.UserName);
                if (isExistsUser != null)
                {
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = "Username already exists" };
                }
                ApplicationUser newUser = new ApplicationUser()
                {
                    Email = registerDTO.Email,
                    UserName = registerDTO.UserName,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    FirstName = registerDTO.FirstName,
                    LastName = registerDTO.LastName
                };

                //Creating the new user
                var createUserResult = await _userManager.CreateAsync(newUser, registerDTO.Password);
                if (!createUserResult.Succeeded)
                {
                    var errorString = "User Creation Failed because: ";
                    foreach (var error in createUserResult.Errors)
                    {
                        errorString += " # " + error.Description;
                    }
                    return new AuthServiceResponseDTO() { IsSucceed = false, Message = errorString };
                }
                //Add a default user role to all users
                await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
                return new AuthServiceResponseDTO() { IsSucceed = true, Message = "User Created Successfully" };
            }
            catch (Exception ex)
            {
                return new AuthServiceResponseDTO() { IsSucceed = false, Message = ex.Message };
            }
        }

        public async Task<AuthServiceResponseDTO> SeedRolesAsync()
        {
            try
            {
                bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
                bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
                bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

                if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                {
                    return  new AuthServiceResponseDTO() { IsSucceed = true,Message= "Roles Seeding is Already Done!" };
                }

                await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
                await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
                await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
                return new AuthServiceResponseDTO() { IsSucceed = true, Message = "Role Seeding Completed" };
            }
            catch (Exception ex)
            {
                return new AuthServiceResponseDTO() { IsSucceed = false, Message = ex.Message };
            }
        }

        private string GenerateJWTAccessToken(List<Claim> authClaims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(issuer: _configuration["JWT:ValidIssuer"], audience: _configuration["JWT:ValidAudience"], expires: DateTime.Now.AddHours(1), claims: authClaims, signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256));

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;

        }
    }
}
