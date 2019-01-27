package com.hermeswaldemarin.microservices.authenticationserver.config;

import com.hermeswaldemarin.microservices.authenticationserver.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.security.NoSuchProviderException;
import java.util.Map;

@Component
@Order(200)
public class CustomAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static String externaltoken = "externaltoken";

    @Autowired(required = true)
    private UserDetailsService userDetailsService;

    @Autowired
    private RestTemplate restTemplate;

    public CustomAuthenticationProvider() {
        super();
    }

    @Autowired
    public UserService userService;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) {
        Map details = (Map)authentication.getDetails();
        if(details.get(externaltoken) != null
                && !"".equals(details.get(externaltoken))){

            String externalToken = (String)details.get(externaltoken);
            String externalProvider = (String)details.get("externalprovider");

            try {
                this.userService.checkExternalProviderCredentials(externalProvider, externalToken , ((CustomUserDetails)userDetails).getExternalid());
            } catch (NoSuchProviderException e) {
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }

        }else{
            String presentedPassword = authentication.getCredentials().toString();

            if(!userDetails.getPassword().equals(presentedPassword)){
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }

        }
    }

    // API


    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) {
        UserDetails loadedUser;
        try {
            loadedUser = this.userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException var6) {
            throw var6;
        } catch (Exception var7) {
            throw new InternalAuthenticationServiceException(var7.getMessage(), var7);
        }

        if (loadedUser == null) {
            throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");
        } else {
            return loadedUser;
        }
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}