using System.ComponentModel.DataAnnotations;

namespace AuthenticationWithGoogle.Models
{
    public class AuthenticatedUser
    {
        public string Access_Token { get; set; }
        public string UserName { get; set; }

    }
}
