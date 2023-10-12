package com.wbg.keycloakdemo.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

//The JwtAuthConverter class is a custom JWT authentication converter that extracts the user's roles
// from the resource access section of the JWT token.Further use in webSecurityConfig
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    private final JwtAuthConverterProperties jwtAuthConverterProperties;

    public JwtAuthConverter(JwtAuthConverterProperties jwtAuthConverterProperties){
        this.jwtAuthConverterProperties = jwtAuthConverterProperties;
    }
    //this method takes a Jwt object as input and returns an AbstractAuthenticationToken object.
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()).collect(Collectors.toSet());
    //This line creates a new JwtAuthenticationToken object and returns it.
        // The JwtAuthenticationToken object contains the JWT token, the user's authorities, and the user's principal.
        return new JwtAuthenticationToken(jwt, authorities, getPrincipalClaimName(jwt));
    }
    //This method takes a Jwt object as input and returns the name of the JWT claim
    // that contains the user's principal.So that it can be further use in the webSecurityConfig class
    private String getPrincipalClaimName(Jwt jwt){
        String claimName = JwtClaimNames.SUB;
        if(jwtAuthConverterProperties.getPrincipalAttribute() != null){
            claimName = jwtAuthConverterProperties.getPrincipalAttribute();
        }
        return jwt.getClaim(claimName);
    }
    // The extractResourceRoles() method does extracts the user's roles
    // from the resource access section of the JWT token by looking up the resourceAccess claim
    // and the roles claim for the configured resource ID.
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt){
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        if(resourceAccess == null
                || (resource = (Map<String, Object>) resourceAccess.get(jwtAuthConverterProperties.getResourceId())) == null
                || (resourceRoles = (Collection<String>) resource.get("roles")) == null ){
            return Set.of();
        }

        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}