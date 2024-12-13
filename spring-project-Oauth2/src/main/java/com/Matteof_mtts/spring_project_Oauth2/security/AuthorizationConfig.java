package com.Matteof_mtts.spring_project_Oauth2.security;

import com.Matteof_mtts.spring_project_Oauth2.config.CustomPasswordAuthenticationConverter;
import com.Matteof_mtts.spring_project_Oauth2.config.CustomPasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        // Configuração minima do Oauth2 authorization server
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);


        // Passar para o configurador do Oauth2 Authorization server, um novo endpointToken com o Converter e o provider;
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                        .tokenEndpoint(oAuth2TokenEndpointConfigurer -> oAuth2TokenEndpointConfigurer.accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
                        .authenticationProvider(new CustomPasswordAuthenticationProvider(authorizationService(), tokenGenerator(), userDetailsService, passwordEncoder()));

        return httpSecurity.build();

    }
}
