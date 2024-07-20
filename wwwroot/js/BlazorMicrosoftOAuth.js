let blazorAuthenticationServiceInstance = null;

function microsoftInitialize(clientId, blazorAuthenticationService) {
    blazorAuthenticationServiceInstance = blazorAuthenticationService;

    // Initialize Microsoft Authentication (MSAL.js)
    const msalConfig = {
        auth: {
            clientId: clientId,
            redirectUri: window.location.origin
        },
        cache: {
            cacheLocation: "localStorage", // This configures where your cache will be stored
            storeAuthStateInCookie: true // Set this to "true" if you are having issues on IE11 or Edge
        },
        system: {
            navigateToLoginRequestUrl: false // Do not navigate to the request URL after login
        }
    };

    MicrosoftAuthentication = new msal.PublicClientApplication(msalConfig);
}

function MicrosoftPrompt() {
    const loginRequest = {
        scopes: ["openid", "profile", "User.Read"]
    };

    MicrosoftAuthentication.loginPopup(loginRequest)
        .then(function (response) {
            blazorCallback(response);
        })
        .catch(function (error) {
            console.error("Failed to authenticate with Microsoft:", error);
        });
}

function blazorCallback(microsoftResponse) {
    if (blazorAuthenticationServiceInstance) {
        blazorAuthenticationServiceInstance.invokeMethodAsync("MicrosoftLogin", {
            IdToken: microsoftResponse.idToken,
            AccessToken: microsoftResponse.accessToken
        });
    } else {
        console.error("Blazor authentication service instance is not initialized.");
    }
}
