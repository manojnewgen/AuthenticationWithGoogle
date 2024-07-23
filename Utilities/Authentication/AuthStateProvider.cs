using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace AuthenticationWithGoogle.Authentication
{
    public class AuthStateProvider : AuthenticationStateProvider, IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ILocalStorageService _localStorageService;
        private readonly AuthenticationState _authState;

        public AuthStateProvider(HttpClient httpClient, ILocalStorageService localStorageService)
        {
            _httpClient = httpClient;
            _localStorageService = localStorageService;
            _authState = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

       
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = await _localStorageService.GetItemAsync<string>("authToken");
            if (string.IsNullOrEmpty(token))
            {
                return _authState;
            }
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(JwtParser.ParseClaimsFromJwt(token), "jwt")));

        }

        public void NotifyUserAuthentication(string token)
        {
            var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(JwtParser.ParseClaimsFromJwt(token), "jwt"));
            var authState = Task.FromResult(new AuthenticationState(authenticatedUser));
            NotifyAuthenticationStateChanged(authState);
        }

        public void NotifyUserAuthentication(ClaimsPrincipal claimsPrincipal)
        {
            var authenticatedUser = claimsPrincipal;
            var authState = Task.FromResult(new AuthenticationState(authenticatedUser));
            NotifyAuthenticationStateChanged(authState);
        }
        public void NotifyUserLogout()
        {
            var authState = Task.FromResult(_authState);
            NotifyAuthenticationStateChanged(authState);
        }
        public async void Dispose()
        {
            _httpClient.Dispose();
            await _localStorageService.RemoveItemAsync("authToken");
            
        }

    }
}
