package com.wbg.keycloakdemo.security;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
// This class configures Spring Security for the application.
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    public static final String ADMIN = "admin";
    public static final String USER = "user";
    //The JwtAuthConverter class is then used by the Spring Security configuration
    // to configure the application's security.
    private final JwtAuthConverter jwtAuthConverter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Define the authorization rules .
        http.
                authorizeHttpRequests(auth ->
                {
                    auth.requestMatchers(HttpMethod.GET, "/test/hello-1").permitAll();
                    auth.requestMatchers(HttpMethod.GET, "/test/hello-2").hasRole(ADMIN);
                    auth.requestMatchers(HttpMethod.GET, "/test/hello-3").hasRole(USER);
                    auth.requestMatchers(HttpMethod.GET, "/test/hello-4").hasAnyRole(ADMIN, USER);
                    auth.anyRequest().authenticated();
                });

        // Configure Spring Security to use the JwtAuthConverter to authenticate users.
        http.
                oauth2ResourceServer(oauth2 -> oauth2.jwt(
                        jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)
                ));

        // Configure Spring Security to use a stateless session management policy.
        http.
                sessionManagement((session) ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}