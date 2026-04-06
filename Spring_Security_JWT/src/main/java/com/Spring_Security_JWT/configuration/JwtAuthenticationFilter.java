package com.Spring_Security_JWT.configuration;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JWTUtils jwtUtils;  
    
	@Autowired
    private OurUserDetailsService ourUserDetailedService;

    JwtAuthenticationFilter(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }
	
	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,
	                               @NonNull HttpServletResponse response,
	                               @NonNull FilterChain filterChain)
	        throws ServletException, IOException {

	    //  Step  Extract Authorization header
	    final String authHeader = request.getHeader("Authorization");

	    String jwtToken = null;
	    String username = null;

	    //  Step  Check if header is present and starts with Bearer
	    if (authHeader != null && authHeader.startsWith("Bearer ")) {

	        //   Extract token
	        jwtToken = authHeader.substring(7);

	        try {
	            //  Extract username from token
	            username = jwtUtils.extractUsername(jwtToken);
	            
//	            Claims claims = Jwts.parserBuilder()
//	                    .setSigningKey(secretKey)
//	                    .build()
//	                    .parseClaimsJws(jwtToken)
//	                    .getBody();
//	            
//	            String role = claims.get("role", String.class);

	            // Convert to authority
//	            List<GrantedAuthority> authorities =
//	                    List.of(new SimpleGrantedAuthority(role));
	            
	        } catch (Exception e) {
	            System.out.println("Invalid JWT Token: " + e.getMessage());
	        }
	    }

	    // Validate token and check authentication
	    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

	        UserDetails userDetails = ourUserDetailedService.loadUserByUsername(username);

	        if (jwtUtils.isTokenValid(jwtToken, userDetails)) {

	            //  Create authentication object
	            UsernamePasswordAuthenticationToken authToken =
	                    new UsernamePasswordAuthenticationToken(
	                            userDetails,
	                            null,
	                            userDetails.getAuthorities()
	                    );

	            authToken.setDetails(
	                    new WebAuthenticationDetailsSource().buildDetails(request)
	            );

	            // Set authentication in context
	            SecurityContextHolder.getContext().setAuthentication(authToken);
	        }
	    }

	    //  Continue filter chain
	    filterChain.doFilter(request, response);
	}

}
