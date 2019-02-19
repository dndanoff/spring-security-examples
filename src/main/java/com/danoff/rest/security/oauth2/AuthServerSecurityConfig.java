package com.danoff.rest.security.oauth2;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import com.danoff.rest.config.AppConfig;
import com.danoff.rest.security.ApplicationRoles;

@Configuration
@EnableResourceServer
@Profile(value = "oauth2")
public class AuthServerSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final AppConfig appConfig;


	@Autowired
	public AuthServerSecurityConfig(AppConfig appConfig) {
		this.appConfig = appConfig;
	}
	
	@Bean
    public PasswordEncoder passwordEncoder() {
    	return new BCryptPasswordEncoder(Integer.valueOf(appConfig.getSecurity().getEncoderStrength()));
    }
	
	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
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
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

	private class CustomUserDetailsService implements UserDetailsService {
		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			if("admin".equals(username)) {
				return new User(username, passwordEncoder().encode("pass"),
						Collections.singleton(new SimpleGrantedAuthority(ApplicationRoles.ADMIN.getRoleName())));
			}
			
			return new User(username, passwordEncoder().encode("pass"),
					Collections.singleton(new SimpleGrantedAuthority(ApplicationRoles.USER.getRoleName())));
		}
	}
}
