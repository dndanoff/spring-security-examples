package com.danoff.rest.security.oauth2;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;

import com.danoff.rest.security.ApplicationRoles;

@Configuration
@EnableResourceServer
@Profile(value = "oauth2")
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId("unique-resource-id").stateless(false);
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
    		.antMatchers("/greetings").hasAnyAuthority(
    						ApplicationRoles.USER.getRoleName(),
	        				ApplicationRoles.ADMIN.getRoleName())
    		.antMatchers("/actuator/**").hasAuthority(ApplicationRoles.ADMIN.getRoleName());
	}


}
