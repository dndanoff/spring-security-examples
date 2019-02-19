package com.danoff.rest.security.oauth2jwt;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

import com.danoff.rest.security.ApplicationRoles;

@Configuration
@EnableResourceServer
@Profile(value = "oauth2jwt")
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	@Autowired
	private DefaultTokenServices defaultTokenServices;
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.tokenServices(defaultTokenServices).resourceId("unique-resource-id").stateless(false);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
        http.
            anonymous().disable()
            .csrf().disable()
            .exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler())
            .and()
            .authorizeRequests()
            .antMatchers("/actuator/info","/actuator/health").permitAll()
    		.antMatchers("/greetings", "/token").hasAnyAuthority(
    						ApplicationRoles.USER.getRoleName(),
	        				ApplicationRoles.ADMIN.getRoleName())
    		.antMatchers("/actuator/**").hasAuthority(ApplicationRoles.ADMIN.getRoleName());
	}

	class CustomAccessTokenConverter extends DefaultAccessTokenConverter {
		 
	    @Override
	    public OAuth2Authentication extractAuthentication(Map<String, ?> claims) {
	        OAuth2Authentication authentication
	         = super.extractAuthentication(claims);
	        authentication.setDetails(claims);
	        return authentication;
	    }
	}
}
