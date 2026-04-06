package com.Spring_Security_JWT.configuration;

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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	
	 private final OurUserDetailsService ourUserDetailsService;
	    private final JwtAuthenticationFilter jwtAuthenticationFilter;
	    private final LoggingFilter loggingFilter;

	    public SecurityConfig(OurUserDetailsService ourUserDetailsService,
	                          JwtAuthenticationFilter jwtAuthenticationFilter,
	                          LoggingFilter loggingFilter) {
	        this.ourUserDetailsService = ourUserDetailsService;
	        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	        this.loggingFilter = loggingFilter;
	    }
	    
	    @Autowired
	    private CustomAuthEntryPoint euAuthEntryPoint;
	    
	    @Autowired
	    private CustomAccessDeniedHandler cuDeniedHandler;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity heSecurity) throws Exception {
		
		heSecurity.csrf(csrf->csrf.disable())
					.authorizeHttpRequests(auth->auth.requestMatchers("/auth/**").permitAll().anyRequest().authenticated())
		
			        .exceptionHandling(ex -> ex
			        		.accessDeniedHandler(cuDeniedHandler)
			                .authenticationEntryPoint(euAuthEntryPoint)  
			        )
					
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

        .addFilterBefore(loggingFilter, JwtAuthenticationFilter.class)

        //  Disable default login form
        .formLogin(form -> form.disable())

        // Disable basic auth (optional)
        .httpBasic(basic -> basic.disable());
		
		return heSecurity.build();
		
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		
		 DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

	        // Set custom user service
	        authProvider.setUserDetailsService(ourUserDetailsService);

	        // Set password encoder
	        authProvider.setPasswordEncoder(passwordEncoder());

	        return authProvider;
		
	}
	
    @Bean  
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {  
        return authenticationConfiguration.getAuthenticationManager();  
    }
	
}
