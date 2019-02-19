package com.danoff.rest.security.oauth2jwt;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.danoff.rest.config.AppConfig;

@Configuration
@Profile(value = "oauth2jwt")
//If Auth/Resource server are separated this must be duplicated
public class CommonTokenConfig {
	
	@Autowired
	private AppConfig appConfig;
	
	@Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }
 
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
    	JwtAccessTokenConverter customConverter = new CustomAccessTokenConverter();
    	customConverter.setSigningKey(appConfig.getSecurity().getKey());
    	
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setAccessTokenConverter(customConverter);
        return converter;
    }
 
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
    
    class CustomAccessTokenConverter extends JwtAccessTokenConverter {
		 //add custom properties to authentication obejct
	    @Override
	    public OAuth2Authentication extractAuthentication(Map<String, ?> claims) {
	        OAuth2Authentication authentication
	         = super.extractAuthentication(claims);
	        authentication.setDetails(claims);
	        return authentication;
	    }
	}
}


