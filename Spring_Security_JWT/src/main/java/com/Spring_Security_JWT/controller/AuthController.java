package com.Spring_Security_JWT.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.Spring_Security_JWT.configuration.JWTUtils;
import com.Spring_Security_JWT.customRepository.UserCustomRepository;
import com.Spring_Security_JWT.entity.Users;
import com.Spring_Security_JWT.request.AuthRequest;
import com.Spring_Security_JWT.service.LoginAttemptService;

@RestController
@RequestMapping("/auth") 
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JWTUtils jUtils;
	
	@Autowired
	private LoginAttemptService loService;
	
    @Autowired
    private UserCustomRepository userRepository;
	
	@PostMapping("/login")
	public String login(@RequestBody AuthRequest request) {
	
		try {
			Authentication auth = authenticationManager.authenticate(
			        new UsernamePasswordAuthenticationToken(
			            request.getUserName(),
			            request.getPassword()
			        )
			    );

			    UserDetails user = (UserDetails) auth.getPrincipal();
			    
			    loService.loginSucceeded(user.getUsername());
			    
			    return jUtils.generateToken(user);
			    
		} catch (Exception e) {
			
			loService.loginFailed(request.getUserName());
		
			return e.getMessage();
		}

	}
	
	@PostMapping("/createUser")
	public String login(@RequestBody Users request) {

		userRepository.saveUser(request);
		
		return "User Successfully created";

	}
	
	@PutMapping("/unlock/{username}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public String unlockAccount(@PathVariable String username) {

		Users user = userRepository.getByUserName(username).orElse(null);

        if (user != null) {
            user.setFailedAttempts(0);
            user.setAccountNonLocked(false);
            userRepository.updateUser(user);
        }

        return "Account unlocked for " + username;
    }
	
	@GetMapping("/test")
	public String test() {
	    return "TEST WORKING";
	}
	
}
