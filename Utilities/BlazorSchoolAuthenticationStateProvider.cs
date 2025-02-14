﻿using AuthenticationWithGoogle.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using System.Security.Claims;

namespace AuthenticationWithGoogle.Utilities;

public class BlazorAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
{
    private readonly BlazorUserService _blazorSchoolUserService;
    private readonly NavigationManager _navigationManager;

    public User? CurrentUser { get; set; } = new();

    public BlazorAuthenticationStateProvider(BlazorUserService blazorSchoolUserService, NavigationManager navigationManager)
    {
         AuthenticationStateChanged += OnAuthenticationStateChangedAsync;
        _blazorSchoolUserService = blazorSchoolUserService;
        _navigationManager = navigationManager;
    }

    private async void OnAuthenticationStateChangedAsync(Task<AuthenticationState> task)
    {
        var authenticationState = await task;

        if (authenticationState is not null)
        {
            CurrentUser = User.FromClaimsPrincipal(authenticationState.User);
        }
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var principal = new ClaimsPrincipal();
        var user = _blazorSchoolUserService.FetchUserFromBrowser();

        if (user is not null)
        {
            var authenticatedUser = await _blazorSchoolUserService.SendAuthenticateRequestAsync(user.Username, user.Password);
            CurrentUser = authenticatedUser;

            if (authenticatedUser is not null)
            {
                principal = authenticatedUser.ToClaimsPrincipal();
            }
        }

        return new(principal);
    }
    
    public async Task LoginAsync(string username, string password)
    {      

        var principal = new ClaimsPrincipal();
        var user = await _blazorSchoolUserService.SendAuthenticateRequestAsync(username, password);
        CurrentUser = user;

        if (user is not null)
        {
            principal = user.ToClaimsPrincipal();
        }

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
    }

    [JSInvokable]
    public void GoogleLogin(GoogleResponse googleResponse)
    {
        var principal = new ClaimsPrincipal();
        var user = User.FromGoogleJwt(googleResponse.Credential);
        CurrentUser = user;

        if (user is not null)
        {
            principal = user.ToClaimsPrincipal();
        }

        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
        _navigationManager.NavigateTo("/");


    }

    public void Logout()
    {
        _blazorSchoolUserService.ClearBrowserUserData();
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new())));
    }

    public void Dispose() => AuthenticationStateChanged -= OnAuthenticationStateChangedAsync;
}
