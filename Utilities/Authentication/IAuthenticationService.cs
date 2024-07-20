using AuthenticationWithGoogle.Models;

namespace AuthenticationWithGoogle.Authentication
{
    public interface IAuthenticationService
    {
        Task<AuthenticatedUser> Login(AuthenticationUser user);
        Task Logout();
    }
}