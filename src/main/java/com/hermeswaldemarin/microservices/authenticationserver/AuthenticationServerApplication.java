package com.hermeswaldemarin.microservices.authenticationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@SpringBootApplication(scanBasePackages = {"com.hermeswaldemarin.microservices.authenticationserver"})
@EnableWebMvc
public class AuthenticationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationServerApplication.class, args);
	}

	@Bean
	public RestTemplate restTemplate(){
		return new RestTemplate();
	}
}
