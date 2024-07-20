let blazorAuthenticationServiceInstance = null;

function blazorGoogleInitialize(clientId, blazorAuthenticationService) {
    if (!clientId || !blazorAuthenticationService) {
        console.error('ClientId or blazorAuthenticationStateProvider is missing.');
        return;
    }

    blazorAuthenticationServiceInstance = blazorAuthenticationService;

    try {
        google.accounts.id.initialize({
            client_id: clientId,
            callback: blazorCallback
        });
        console.info('Google Identity Services initialized successfully.');
    } catch (error) {
        console.error('Error initializing Google Identity Services:', error);
    }
}

function blazorGooglePrompt() {
    try {
        google.accounts.id.prompt((notification) => {
            if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
                console.info('Google prompt not displayed or skipped.');
                console.info('Not displayed reason:', notification.getNotDisplayedReason());
                console.info('Skipped reason:', notification.getSkippedReason());
            }
        });
        console.info('Google prompt invoked successfully.');
    } catch (error) {
        console.error('Error invoking Google prompt:', error);
    }
}

function blazorCallback(googleResponse) {
    if (!blazorAuthenticationServiceInstance) {
        console.error('blazorAuthenticationStateProviderInstance is not set.');
        return;
    }
    let GoogleLogin = false;

    if (googleResponse) {
        try {
            blazorAuthenticationServiceInstance.invokeMethodAsync("GoogleLogin", {
                clientId: googleResponse.clientId,
                selectedBy: googleResponse.select_by,
                credential: googleResponse.credential
            });
            console.info('Google login callback invoked successfully.');
        } catch (error) {
            console.error('Error invoking Google login callback:', error);
        }
    } else {
        console.error('Google response is null or undefined.');
    }

}

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
