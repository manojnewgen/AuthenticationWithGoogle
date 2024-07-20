namespace AuthenticationWithGoogle.Models;

public class GoogleResponse
{
    public string ClientId { get; set; } = "";
    public string SelectedBy { get; set; } = "";
    public string Credential { get; set; } = "";
}

public class MicrosoftResponse { 
    public string IdToken { get; set; }= "";
    public string AccessToken { get; set; } = "";
}

