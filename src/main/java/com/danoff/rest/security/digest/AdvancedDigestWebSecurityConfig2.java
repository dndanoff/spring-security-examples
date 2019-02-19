package com.danoff.rest.security.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

import com.danoff.rest.config.AppConfig;
import com.danoff.rest.security.ApplicationRoles;

@Configuration
@Profile(value = "digest-advanced")
public class AdvancedDigestWebSecurityConfig2 extends WebSecurityConfigurerAdapter {

	private final AppConfig appConfig;

	@Autowired
	public AdvancedDigestWebSecurityConfig2(AppConfig appConfig) {
		this.appConfig = appConfig;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
	}

	@Bean
	public DigestAuthenticationEntryPoint adminAauthenticationEntryPoint() {
		DigestAuthenticationEntryPoint authenticationEntryPoint = new DigestAuthenticationEntryPoint();
		authenticationEntryPoint.setKey(appConfig.getSecurity().getKey());
		authenticationEntryPoint.setRealmName(appConfig.getRealm().getAdmin());

		return authenticationEntryPoint;
	}

	 @Override
	 protected void configure(HttpSecurity http) throws Exception {
	 	DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setAuthenticationEntryPoint(adminAauthenticationEntryPoint());
		filter.setUserDetailsService(userDetailsService());
		filter.setPasswordAlreadyEncoded(true);
		
		 http
		 	.addFilter(filter)
     		.exceptionHandling()
	        	.authenticationEntryPoint(adminAauthenticationEntryPoint())
	 	.and()
		        .httpBasic()
	     .and()
		        .sessionManagement()
		        	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	     .and()
	     	.authorizeRequests()
	     		.antMatchers("/actuator/info","/actuator/health").permitAll()
	     		.anyRequest().authenticated();

	}
	 
	private String digest(String username, String password) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No MD5 algorithm available!");
		}

		String data = username + ":" + appConfig.getRealm().getAdmin() + ":" + password;

		return new String(Hex.encode(digest.digest(data.getBytes())));

	}

	private class CustomUserDetailsService implements UserDetailsService {
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return new User(username, "pass",
					Collections.singleton(new SimpleGrantedAuthority(ApplicationRoles.USER.getRoleName())));
		}
	}
}
