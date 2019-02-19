package com.danoff.rest.security.oauth2jwt;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
@Profile(value = "oauth2jwt")
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

	private static final String GRANT_TYPE_PASSWORD = "password";
	private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
	private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
	private static final String GRANT_TYPE_IMPLICIT = "implicit";
	
	private static final String SCOPE_READ = "read";
	private static final String SCOPE_WRITE = "write";

	
	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManagerBean;
	
	@Autowired
	private JwtAccessTokenConverter accessTokenConverter;
	
	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
    
    @Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    	TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(
          Arrays.asList(new CustomTokenEnhancer(), accessTokenConverter));
    	
    	
    	endpoints.tokenStore(tokenStore)
				.tokenEnhancer(tokenEnhancerChain)
				.authenticationManager(authenticationManagerBean);
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
		configurer
				.inMemory()
				.withClient("rest-api-resource-server")
				.secret(passwordEncoder.encode("rest-api-resource-server-secret"))
				.authorizedGrantTypes(GRANT_TYPE_PASSWORD,
										GRANT_TYPE_AUTHORIZATION_CODE,
										GRANT_TYPE_REFRESH_TOKEN,
										GRANT_TYPE_IMPLICIT )
				.scopes(SCOPE_READ, SCOPE_WRITE)
				.resourceIds("unique-resource-id")
				//5 minutes
				.accessTokenValiditySeconds(60*5)
				//3 hours
				.refreshTokenValiditySeconds(60*60*3);
	}

	
	
	class CustomTokenEnhancer implements TokenEnhancer {
		 
	    @Override
	    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
	        User user = (User) authentication.getPrincipal();
	        final Map<String, Object> additionalInfo = new HashMap<>();
	 
	        additionalInfo.put("authorities", user.getAuthorities());
	        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
	 
	        return accessToken;
	    }
	 
	}

}
