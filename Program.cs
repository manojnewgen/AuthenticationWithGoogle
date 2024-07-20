using AuthenticationWithGoogle;
using AuthenticationWithGoogle.Authentication;
using AuthenticationWithGoogle.Utilities;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");



builder.Services.AddScoped<AuthenticationDataMemoryStorage>();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddScoped<BlazorUserService>();
builder.Services.AddScoped<BlazorAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<BlazorAuthenticationStateProvider>());
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<AuthenticationStateProvider, AuthStateProvider>();
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("https://localhost:7029/") });
builder.Services.AddAuthorizationCore();

await builder.Build().RunAsync();
