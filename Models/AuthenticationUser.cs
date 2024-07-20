using System.ComponentModel.DataAnnotations;

namespace AuthenticationWithGoogle.Models
{
    public class AuthenticationUser
    {

        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
