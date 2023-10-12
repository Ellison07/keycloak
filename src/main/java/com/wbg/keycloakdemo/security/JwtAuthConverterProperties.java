package com.wbg.keycloakdemo.security;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "jwt.auth.converter")

//The JwtAuthConverterProperties class is used by the JwtAuthConverter class
// to authenticate users and extract their roles from the JWT token.
public class JwtAuthConverterProperties {
    private String resourceId;
    private String principalAttribute;
}