package com.danoff.rest.security.basic;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.danoff.rest.config.AppConfig;
import com.danoff.rest.security.ApplicationRoles;

@Configuration
@Profile(value="basic-advanced")
public class BasicWebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final AppConfig appConfig;
	
	@Autowired
	public BasicWebSecurityConfig(AppConfig appConfig){
		this.appConfig = appConfig;
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
     
//    @Bean
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
    
    class CustomUserDetailsService implements UserDetailsService {
    	
        private final Map<String, UserObject> users = new HashMap<>();

        public CustomUserDetailsService() {
        	populateUsers();
        }
        
        private void populateUsers() {
    		users.put("admin",
    				new UserObject("admin",
    								passwordEncoder().encode("admin@13"),
    								ApplicationRoles.ADMIN.getRoleName(),
    								ApplicationRoles.USER.getRoleName()));
    		users.put("user",
    				new UserObject("user",
    								passwordEncoder().encode("pass"),
    								ApplicationRoles.USER.getRoleName()));
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            UserObject user = users.get(username);
            if (user == null) {
                throw new UsernameNotFoundException("User not found by name: " + username);
            }
            return toUserDetails(user);
        }

        private UserDetails toUserDetails(UserObject userObject) {
            return User.withUsername(userObject.name)
                       .password(userObject.password)
                       .roles(userObject.roles).build();
        }
    }
    
    private class UserObject {
    	
        private String name;
        private String password;
        private String[] roles;

        public UserObject(String name, String password, String... roles) {
            this.name = name;
            this.password = password;
            this.roles = roles;
        }
    }
}
