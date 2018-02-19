package com.hermeswaldemarin.microservices.authenticationserver.services;

import com.hermeswaldemarin.microservices.authenticationserver.config.CustomJdbcUserDetailsManager;
import com.hermeswaldemarin.microservices.authenticationserver.config.CustomUserDetails;
import com.hermeswaldemarin.microservices.authenticationserver.model.User;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.mail.internet.MimeMessage;
import java.nio.charset.Charset;
import java.security.NoSuchProviderException;
import java.util.Arrays;

@Component
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private UserDetailsService userDetailsService;

    private RestTemplate restTemplate;

    @Autowired
    public JavaMailSender emailSender;

    @Value("classpath:mail-confirmation.html")
    private Resource mailConfirmation;

    @Value("classpath:logo.jpeg")
    private Resource logo;

    @Value("${microservices.series.authentication-server.url}")
    private String urlAutenticationServer;


    public UserService(UserDetailsService userDetailsService, RestTemplate restTemplate){
        this.userDetailsService = userDetailsService;
        this.restTemplate = restTemplate;
    }

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public void checkExternalProviderCredentials(String externalProvider, String externalAccessToken, String externalId) throws NoSuchProviderException {
        if(externalProvider.equals("facebook")){
            ResponseEntity<String> retorno = restTemplate.getForEntity("https://graph.facebook.com/me?access_token=" + externalAccessToken, String.class);
            try {
                JSONObject object = new JSONObject(retorno.getBody());

                if(!object.get("id").equals(externalId)){
                    throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
                }
            } catch (JSONException e) {
                log.error("Error", e);
            }

        }else if(externalProvider.equals("local")){
            if(externalAccessToken.equals("")){
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }
        }else{
            throw new NoSuchProviderException("Invalid Provider");
        }
    }

    public void createUser(User user) {
        try{
            UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
            log.info(userDetails.getUsername());
        }catch (UsernameNotFoundException e){

            try {
                this.checkExternalProviderCredentials(user.getExternalProvider(), user.getExternalAccessToken() , user.getExternalId());
            } catch (NoSuchProviderException e1) {
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }
            CustomJdbcUserDetailsManager customService = (CustomJdbcUserDetailsManager) userDetailsService;

            CustomUserDetails userTemp = new CustomUserDetails(
                    new org.springframework.security.core.userdetails.User(
                            user.getUsername(),
                            user.getExternalProvider().equals("local") ? user.getExternalAccessToken() : "!?microservices#@internal#2017#",
                            false,
                            true,
                            true,
                            true,
                            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))

                    ),
                    user.getExternalId()
            );

            customService.createUser(userTemp);
            String token = customService.createMailToken(userTemp);

            MimeMessagePreparator preparator = new MimeMessagePreparator() {

                public void prepare(MimeMessage mimeMessage) throws Exception {
                    MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

                    helper.setSubject("Welcome to HermesWaldemarin Microservices Series.");
                    helper.setFrom("contact@hermeswaldemarin.com.br");
                    helper.setTo(user.getUsername());

                    String content = IOUtils.toString(mailConfirmation.getInputStream(), Charset.defaultCharset()).replace("{{token}}", token).replace("{{autenticationserver-url}}", urlAutenticationServer);

                    // Add an inline resource.
                    // use the true flag to indicate you need a multipart message
                    helper.setText(content, true);
                    helper.addInline("company-logo", logo);
                }
            };

            emailSender.send(preparator);
        }
    }
}
