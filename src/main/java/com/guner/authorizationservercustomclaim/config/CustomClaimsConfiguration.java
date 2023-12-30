package com.guner.authorizationservercustomclaim.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class CustomClaimsConfiguration {
	/*
	custom claim
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					claims.put("claim-1", "value-1");
					claims.put("claim-2", "value-2");
				});
			}
		};
	}
	*/

	/**
	 * result JWT
	 *  {
	 *   "sub": "user",
	 *   "aud": "client1",
	 *   "nbf": 1703966481,
	 *   "scope": [
	 *     "read",
	 *     "openid",
	 *     "write"
	 *   ],
	 *   "roles": [
	 *     "USER"
	 *   ],
	 *   "iss": "http://localhost:8000",
	 *   "exp": 1703970081,
	 *   "iat": 1703966481
	 * }
	 *
	 *
	 */
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
							.stream()
							.map(c -> c.replaceFirst("ROLE_", ""))
							.collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
					claims.put("roles", roles);
				});
			}
		};
	}
}