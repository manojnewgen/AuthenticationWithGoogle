using AuthenticationWithGoogle.Models;
using AuthenticationWithGoogle.Utilities.Authentication;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;
using JsonSerializer = System.Text.Json.JsonSerializer;

namespace AuthenticationWithGoogle.Authentication
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly HttpClient _httpClient;
        private readonly ILocalStorageService _localStorageService;
        private readonly AuthenticationStateProvider _authenticationStateProvider;
        public User? CurrentUser { get; set; } = new();
        NavigationManager _navigationManager;
        private readonly IConfiguration _config;

        public AuthenticationService(HttpClient httpClient,
                                    ILocalStorageService localStorageService,
                                    AuthenticationStateProvider authenticationStateProvider,
                                    NavigationManager navigationManager, IConfiguration config)
        {
            _httpClient = httpClient;
            // _httpClient.BaseAddress = new Uri("https://localhost:7029/");
            _localStorageService = localStorageService;
            _authenticationStateProvider = authenticationStateProvider;
            _navigationManager = navigationManager;
            _config = config;
        }
        /// <summary>
        ///Call the API to login
        ///Save the token in local storage
        ///Notify the AuthenticationStateProvider
        ///Return the authenticated user
        ///set httpsClient headers
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<AuthenticatedUser> Login(AuthenticationUser user)
        {

            var data = new LoginRequestModel
            {
                grant_type = "password",
                EmailAddress = user.Email,
                Password = user.Password
            };

            var serializedUser = JsonConvert.SerializeObject(data);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, "api/Auth/authenticate-custom")
            {
                Content = new StringContent(serializedUser)
            };

            requestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var response = await _httpClient.SendAsync(requestMessage);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var authContent = await response.Content.ReadAsStringAsync();
            var authUser = JsonSerializer.Deserialize<AuthenticatedUser>(authContent,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (!JwtValidator.ValidateJwtToken(authUser.Access_Token, "e959f9c5-f002-4c06-9fef-f650ca69c98c", "authApi", "blazorWasm"))
            {
                return null;
            }

            await _localStorageService.SetItemAsync("authToken", authUser.Access_Token);
            ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(authUser.Access_Token);

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authUser.Access_Token);

            return authUser;
        }




        [JSInvokable]
        public async void GoogleLogin(GoogleResponse googleResponse)
        {

            var principal = new ClaimsPrincipal();
            if (googleResponse is not null)
            {
                var googleToken = googleResponse.Credential;
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, "api/auth/validate-google-token")
                {
                    Content = new StringContent(JsonSerializer.Serialize(googleToken), Encoding.UTF8, "application/json")
                };

                var response = await _httpClient.SendAsync(requestMessage);

                if (!response.IsSuccessStatusCode)
                {
                    // Handle the error
                    return;
                }

                var authContent = await response.Content.ReadAsStringAsync();
                var authUser = JsonSerializer.Deserialize<AuthenticatedUser>(authContent,
               new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                _localStorageService.SetItemAsync("authToken", authUser.Access_Token);

                ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(authUser.Access_Token);

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authUser.Access_Token);
            }

            _navigationManager.NavigateTo("/");


        }

        [JSInvokable]
        public async void MicrosoftLogin(MicrosoftResponse mResponse)
        {
            var principal = new ClaimsPrincipal();
            if (mResponse is not null)
            {
                // Use the Access_token for making API calls
                var authToken = mResponse.IdToken;

                var requestMessage = new HttpRequestMessage(HttpMethod.Post, "api/auth/add-role-to-token")
                {
                    Content = new StringContent(JsonSerializer.Serialize(authToken), Encoding.UTF8, "application/json")
                };

                var response = await _httpClient.SendAsync(requestMessage);

                if (!response.IsSuccessStatusCode)
                {
                    // Handle the error
                    return;
                }

                var authContent = await response.Content.ReadAsStringAsync();
                var authUser = JsonSerializer.Deserialize<AuthenticatedUser>(authContent,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                // Store the Access_token for future API calls
                await _localStorageService.SetItemAsync("authToken", authUser.Access_Token);

                ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(authUser.Access_Token);

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authUser.Access_Token);
            }

            _navigationManager.NavigateTo("/");
        }

        public async Task Logout()
        {
            await _localStorageService.RemoveItemAsync("authToken");
            ((AuthStateProvider)_authenticationStateProvider).NotifyUserLogout();
            _httpClient.DefaultRequestHeaders.Authorization = null;
        }
    }
}


