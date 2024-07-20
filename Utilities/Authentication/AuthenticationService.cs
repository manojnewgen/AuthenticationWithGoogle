using AuthenticationWithGoogle.Models;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
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

            await _localStorageService.SetItemAsync("authToken", authUser.Access_Token);
            ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(authUser.Access_Token);

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authUser.Access_Token);

            return authUser;
        }




        [JSInvokable]
        public void GoogleLogin(GoogleResponse googleResponse)
        {

            var principal = new ClaimsPrincipal();
            if (googleResponse is not null)
            {
                _localStorageService.SetItemAsync("authToken", googleResponse.Credential);
                ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(googleResponse.Credential);

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", googleResponse.Credential);
            }

            _navigationManager.NavigateTo("/");


        }

        [JSInvokable]
        public void MicrosoftLogin(MicrosoftResponse mResponse)
        {
            var principal = new ClaimsPrincipal();
            if (mResponse is not null)
            {
                _localStorageService.SetItemAsync("authToken", mResponse.AccessToken);
                ((AuthStateProvider)_authenticationStateProvider).NotifyUserAuthentication(mResponse.AccessToken);

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", mResponse.AccessToken);
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


