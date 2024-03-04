using System.ComponentModel.DataAnnotations;

namespace DotnetRoleBasedAuthAPI.Core.DTOs
{
    public class UpdatePermissionDTO
    {
        [Required(ErrorMessage = "Username is required")]
        public string UserName { get; set; }
        
    }
}
