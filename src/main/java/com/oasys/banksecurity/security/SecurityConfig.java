package com.oasys.banksecurity.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.util.pattern.PathPattern;

import jakarta.websocket.server.PathParam;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	@Autowired JwtFilter filters;

	@Bean
	UserDetailsService UserDetailService() {
		return new UserInfoUserDetailsService();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		  return http.csrf(csrf -> csrf.disable())
		            .authorizeHttpRequests(auth -> {
		                auth.requestMatchers("/bank/insertuser","/bank/getmsg","/bank/authenticate").permitAll();
		                auth.requestMatchers("/bank/getuser","bank/getbyid/{id}","/bank/newaccount").hasAnyRole("USER", "ADMIN");
		                auth.requestMatchers("/bank/getall","bank/getbyid/{id}","/bank/newaccount").hasAnyRole("ADMIN");
		            })
		            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
		            .authenticationProvider(authenticationProvider()).addFilterAfter(filters, UsernamePasswordAuthenticationFilter.class).build();
	}

	@Bean
	AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAutheticate = new DaoAuthenticationProvider();
		daoAutheticate.setUserDetailsService(UserDetailService());
		daoAutheticate.setPasswordEncoder(passwordEncoder());
		return daoAutheticate;
	}
	 @Bean
	    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
	        return config.getAuthenticationManager();
	    }

	
	 @Bean
	 CorsConfigurationSource corsConfigurationSource() {
	         CorsConfiguration configuration = new CorsConfiguration();
	         configuration.setAllowedOrigins(Arrays.asList("*"));
	         configuration.setAllowedMethods(Arrays.asList("GET", "POST", "OPTIONS", "DELETE", "PUT", "PATCH"));
	         configuration.setAllowedHeaders(Arrays.asList("X-Requested-With", "Origin", "Content-Type", "Accept", "Authorization"));
	         configuration.setAllowCredentials(true);
	         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	         source.registerCorsConfiguration("/**", configuration);
	         return source;
	     }}


