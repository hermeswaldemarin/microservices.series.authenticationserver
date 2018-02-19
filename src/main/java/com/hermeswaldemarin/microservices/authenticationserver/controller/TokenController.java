package com.hermeswaldemarin.microservices.authenticationserver.controller;

import com.hermeswaldemarin.microservices.authenticationserver.config.CustomJdbcUserDetailsManager;
import com.hermeswaldemarin.microservices.authenticationserver.config.CustomUserDetails;
import com.hermeswaldemarin.microservices.authenticationserver.model.User;
import com.hermeswaldemarin.microservices.authenticationserver.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Controller
public class TokenController {

    @Resource(name = "tokenServices")
    ConsumerTokenServices tokenServices;

    @Resource(name = "tokenStore")
    TokenStore tokenStore;

    @Value("${microservices.series.authentication-server.redirecturl}")
    String tokenConfirmationRedirectUrl;

    @Autowired(required = true)
    private UserDetailsService userDetailsService;

    @Autowired
    private UserService userService;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private static final Logger log = LoggerFactory.getLogger(UserService.class);


    @RequestMapping(method = RequestMethod.POST, value = "/oauth/token/revokeById/{tokenId}")
    @ResponseBody
    public void revokeToken(HttpServletRequest request, @PathVariable String tokenId) {
        tokenServices.revokeToken(tokenId);
    }

    @RequestMapping(method = RequestMethod.GET, value = "/tokens")
    @ResponseBody
    public List<String> getTokens() {
        List<String> tokenValues = new ArrayList<>();
        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId("sampleClientId");
        if (tokens != null) {
            for (OAuth2AccessToken token : tokens) {
                tokenValues.add(token.getValue());
            }
        }
        return tokenValues;
    }

    @RequestMapping(method = RequestMethod.POST, value = "/tokens/revokeRefreshToken/{tokenId:.*}")
    @ResponseBody
    public String revokeRefreshToken(@PathVariable String tokenId) {
        if (tokenStore instanceof JdbcTokenStore) {
            ((JdbcTokenStore) tokenStore).removeRefreshToken(tokenId);
        }
        return tokenId;
    }

    @RequestMapping(method = RequestMethod.POST, value = "/user-create")
    public ResponseEntity<String> postMessage(@RequestBody User user) {

        userService.createUser(user);

        return new ResponseEntity<>("OK", HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.GET, value = "/confirm-token")
    @ResponseStatus(HttpStatus.OK)
    public void confirmEmailToken(@RequestParam String token, HttpServletResponse response) {

        CustomJdbcUserDetailsManager customService = (CustomJdbcUserDetailsManager) userDetailsService;

        String username = customService.getUserNameByToken(token);

        UserDetails userDetails = customService.loadUserByUsername(username);
        UserDetails userUpdate = new CustomUserDetails(
                new org.springframework.security.core.userdetails.User(
                userDetails.getUsername(),
                userDetails.getPassword(),
                true,
                userDetails.isAccountNonExpired(),
                userDetails.isCredentialsNonExpired(),
                userDetails.isAccountNonLocked(),
                userDetails.getAuthorities()
                ),
                ((CustomUserDetails)userDetails).getExternalid()
        );
        customService.updateUser(userUpdate);

        try {
            response.sendRedirect(tokenConfirmationRedirectUrl);
        } catch (IOException e) {
            log.error("Error", e);
        }

    }

}