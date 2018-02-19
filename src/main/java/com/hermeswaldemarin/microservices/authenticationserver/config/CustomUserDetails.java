package com.hermeswaldemarin.microservices.authenticationserver.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Objects;

public class CustomUserDetails extends User {

    private String externalid;
    private UserDetails user;

    public CustomUserDetails(UserDetails user, String externalid) {
        super(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(), user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
        this.externalid = externalid;
        this.user = user;
    }

    public String getExternalid() {
        return externalid;
    }

    public void setExternalid(String externalid) {
        this.externalid = externalid;
    }

    public UserDetails getUser() {
        return user;
    }

    public void setUser(UserDetails user) {
        this.user = user;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CustomUserDetails that = (CustomUserDetails) o;
        return Objects.equals(externalid, that.externalid) &&
                Objects.equals(user, that.user);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), externalid, user);
    }
}
