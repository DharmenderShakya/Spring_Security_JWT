package com.Spring_Security_JWT.configuration;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.Spring_Security_JWT.customRepository.UserCustomRepository;
import com.Spring_Security_JWT.entity.Users;

@Service
public class OurUserDetailsService implements UserDetailsService{

	@Autowired 
	private UserCustomRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users user = userRepository.getByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

		System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-="+" "+user.getFailedAttempts());
		
		System.out.println("flag -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-="+" "+user.isAccountNonLocked());
		
	    if (user.isAccountNonLocked()) {
	    	System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-="+" "+"Account is locked!");
	        throw new LockedException("Account is locked!");
	    }
		System.out.println("");
        return new User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(
                        new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
                )
        );
	}

}
