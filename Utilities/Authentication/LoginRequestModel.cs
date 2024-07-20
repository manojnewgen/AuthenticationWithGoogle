namespace AuthenticationWithGoogle.Authentication
{
    internal class LoginRequestModel
    {
        public string grant_type { get; set; }
        public string EmailAddress { get; set; }
        public string Password { get; set; }
    }
}