package com.danoff.rest.security.basic;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.danoff.rest.config.AppConfig;
import com.danoff.rest.security.ApplicationRoles;

@Configuration
@Profile(value="basic")
public class BasicInMemoryWebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final AppConfig appConfig;
	
	@Autowired
	public BasicInMemoryWebSecurityConfig(AppConfig appConfig){
		this.appConfig = appConfig;
	}
	
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
    	auth.inMemoryAuthentication()
        .withUser("admin").password(passwordEncoder().encode("admin")).roles(ApplicationRoles.ADMIN.getRoleName())
        .and()
        .withUser("user").password(passwordEncoder().encode("pass")).roles(ApplicationRoles.USER.getRoleName());
    }
	
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	auth.inMemoryAuthentication()
        .withUser("admin").password(passwordEncoder().encode("admin")).roles(ApplicationRoles.ADMIN.getRoleName())
        .and()
        .withUser("user").password(passwordEncoder().encode("pass")).roles(ApplicationRoles.USER.getRoleName());
    }
	
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        	.exceptionHandling()
	        	.defaultAuthenticationEntryPointFor(adminAauthenticationEntryPoint(), new AntPathRequestMatcher("/management/**"))
	        	.defaultAuthenticationEntryPointFor(generalAuthenticationEntryPoint(), new AntPathRequestMatcher("/api/**"))
    	.and()
	        .httpBasic()
        .and()
	        .sessionManagement()
	        	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        	.authorizeRequests()
        		.antMatchers("/actuator/info","/actuator/health").permitAll()
        		.antMatchers("/greetings").hasAnyRole(
        				ApplicationRoles.USER.getRoleName(),
        				ApplicationRoles.ADMIN.getRoleName())
        		.anyRequest().hasRole(ApplicationRoles.ADMIN.getRoleName());
	}
	 
    @Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(Integer.valueOf(appConfig.getSecurity().getEncoderStrength()));
	}
	
	@Bean
	public AuthenticationEntryPoint generalAuthenticationEntryPoint(){
	    BasicAuthenticationEntryPoint entryPoint = 
	      new BasicAuthenticationEntryPoint();
	    entryPoint.setRealmName(appConfig.getRealm().getApi());
	    return entryPoint;
	}
	
	@Bean
	public AuthenticationEntryPoint adminAauthenticationEntryPoint(){
	    BasicAuthenticationEntryPoint entryPoint = 
	      new BasicAuthenticationEntryPoint();
	    entryPoint.setRealmName(appConfig.getRealm().getAdmin());
	    return entryPoint;
	}

}
