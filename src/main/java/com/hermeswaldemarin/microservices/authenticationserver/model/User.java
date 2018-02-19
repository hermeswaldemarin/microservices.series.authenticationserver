package com.hermeswaldemarin.microservices.authenticationserver.model;

public class User {
    String username;
    String externalId;
    String externalProvider;
    String externalAccessToken;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getExternalProvider() {
        return externalProvider;
    }

    public void setExternalProvider(String externalProvider) {
        this.externalProvider = externalProvider;
    }

    public String getExternalAccessToken() {
        return externalAccessToken;
    }

    public void setExternalAccessToken(String externalAccessToken) {
        this.externalAccessToken = externalAccessToken;
    }
}
