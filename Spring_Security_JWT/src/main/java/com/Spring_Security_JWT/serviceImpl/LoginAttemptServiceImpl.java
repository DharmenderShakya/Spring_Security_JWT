package com.Spring_Security_JWT.serviceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.Spring_Security_JWT.customRepository.UserCustomRepository;
import com.Spring_Security_JWT.entity.Users;
import com.Spring_Security_JWT.service.LoginAttemptService;

@Service
public class LoginAttemptServiceImpl implements LoginAttemptService {

	private static final int MAX_ATTEMPTS = 5;

    @Autowired
    private UserCustomRepository userRepository;
    
    public void loginSucceeded(String username) {
    	
        Users user = userRepository.getByUserName(username).orElse(null);

        if (user != null) {
            user.setFailedAttempts(0);
            userRepository.updateUser(user);
        }
    }

    public void loginFailed(String username) {
        Users user = userRepository.getByUserName(username).orElse(null);

        if (user != null) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            user.setAccountNonLocked(false);
            userRepository.updateUser(user);
            if (attempts >= MAX_ATTEMPTS) {
            	user.setAccountNonLocked(true);
            	userRepository.updateUser(user);
                System.out.println("Account locked for: " + username);
            }
        }
    }

}
