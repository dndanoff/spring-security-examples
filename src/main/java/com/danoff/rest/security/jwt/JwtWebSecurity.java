package com.danoff.rest.security.jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import com.danoff.rest.config.AppConfig;
import com.danoff.rest.security.ApplicationRoles;

@Configuration
@Profile(value = "jwt")
public class JwtWebSecurity extends WebSecurityConfigurerAdapter {

	private final AppConfig appConfig;

	@Autowired
	public JwtWebSecurity(AppConfig appConfig) {
		this.appConfig = appConfig;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
	}
	
	@Bean
	public JwtTokenProvider jwtTokenProvider() {
		return new JwtTokenProvider(appConfig, userDetailsService());
	}

	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(Integer.valueOf(appConfig.getSecurity().getEncoderStrength()));
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
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.addFilterBefore(new JwtTokenFilter(jwtTokenProvider()), UsernamePasswordAuthenticationFilter.class)
		.httpBasic().disable()
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        	.authorizeRequests()
        		.antMatchers("/actuator/info","/actuator/health","/auth/token").permitAll()
        		.antMatchers("/greetings").hasAnyRole(
        				ApplicationRoles.USER.getRoleName(),
        				ApplicationRoles.ADMIN.getRoleName())
        		.antMatchers("/actuator/**").hasRole(ApplicationRoles.ADMIN.getRoleName())
        		.anyRequest().authenticated();
	}

	private class JwtTokenFilter extends GenericFilterBean {
		private JwtTokenProvider jwtTokenProvider;

		public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
			this.jwtTokenProvider = jwtTokenProvider;
		}

		@Override
		public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
				throws IOException, ServletException {
			String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
			if (token != null && jwtTokenProvider.validateToken(token)) {
				Authentication auth = token != null ? jwtTokenProvider.getAuthentication(token) : null;
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
			filterChain.doFilter(req, res);
		}
	}

	public class CustomUserDetailsService implements UserDetailsService {

		private final Map<String, UserObject> users = new HashMap<>();

		public CustomUserDetailsService() {
			populateUsers();
		}

		public Optional<UserObject> findByUsername(String username) {
			return Optional.ofNullable(users.get(username));
		}
		
		private void populateUsers() {
			users.put("admin", new UserObject("admin", passwordEncoder().encode("admin@13"),
					ApplicationRoles.ADMIN.getRoleName(), ApplicationRoles.USER.getRoleName()));
			users.put("user",
					new UserObject("user", passwordEncoder().encode("pass"), ApplicationRoles.USER.getRoleName()));
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
			return User.withUsername(userObject.name).password(userObject.password).roles(userObject.roles.toArray(new String[] {})).build();
		}
	}

	public class UserObject {

		private final String name;
		private final String password;
		private final List<String> roles;

		public UserObject(String name, String password, String... roles) {
			this.name = name;
			this.password = password;
			this.roles = Stream.of(roles).collect(Collectors.toList());
		}

		public String getName() {
			return name;
		}


		public String getPassword() {
			return password;
		}

		public List<String> getRoles() {
			return new ArrayList<>(roles);
		}
	}
}
