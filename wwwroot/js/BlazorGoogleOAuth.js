let blazorAuthenticationStateProviderInstance = null;

function blazorGoogleInitialize(clientId, blazorAuthenticationStateProvider) {
    if (!clientId || !blazorAuthenticationStateProvider) {
        console.error('ClientId or blazorAuthenticationStateProvider is missing.');
        return;
    }

    blazorAuthenticationStateProviderInstance = blazorAuthenticationStateProvider;

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
    if (!blazorAuthenticationStateProviderInstance) {
        console.error('blazorAuthenticationStateProviderInstance is not set.');
        return;
    }
    let GoogleLogin = false;

    if (googleResponse) {
        try {
            blazorAuthenticationStateProviderInstance.invokeMethodAsync("GoogleLogin", {
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