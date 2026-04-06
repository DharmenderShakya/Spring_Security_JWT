package com.Spring_Security_JWT.configuration;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component  
public class JWTUtils {  
  
    // Encryption key for JWT  
    private SecretKey secretKey;  
   
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24;;
  
    public JWTUtils(){  
    	
        String secreteString = "ghjklj54664twetwet54t5ew7t87we8rt78tw7t87w";
        
        byte[] keyBytes = Decoders.BASE64.decode(secreteString);
        
        this.secretKey = Keys.hmacShaKeyFor(secreteString.getBytes(StandardCharsets.UTF_8));
        
    }  
 
    public String generateToken(UserDetails userDetails){
    	
        String role = userDetails.getAuthorities()
                .stream()
                .findFirst()
                .get()
                .getAuthority(); 
    	
        return Jwts.builder()
                .setSubject(userDetails.getUsername()) // username
                .claim("role", role)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact(); 
        
    }  
  
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (EXPIRATION_TIME * 7))) // 7 days
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    } 
  
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }
  
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) {

        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claimsTFunction.apply(claims);
    }
  
    public boolean isTokenValid(String token, UserDetails userDetails) {

        final String username = extractUsername(token);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
  
  
    private boolean isTokenExpired(String token) {
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }
    
}


