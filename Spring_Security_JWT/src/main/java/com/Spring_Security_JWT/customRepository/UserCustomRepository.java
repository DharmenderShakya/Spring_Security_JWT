package com.Spring_Security_JWT.customRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import com.Spring_Security_JWT.entity.Users;
import com.Spring_Security_JWT.enums.Role;

@Repository
public class UserCustomRepository {

    // Store user data in memory
    private Map<String, Users> userStore = new HashMap<>();

    public UserCustomRepository() {

        // Initialize users ONCE
        userStore.put("dharmender", createUser("dharmender", Role.USER));
        userStore.put("ravi", createUser("ravi", Role.SUPER_ADMIN));
        userStore.put("roshan", createUser("roshan", Role.MODERATOR));
    }

    private Users createUser(String username, Role role) {
        Users user = new Users();
        user.setUserName(username);
        user.setPassword("$2a$10$E6agxwiMV2wGIsgUd.OWeuQJL8ssURRFwubZOhUUsn0CBNySUkaou"); // admin123
        user.setRole(role);
        user.setAccountNonLocked(false);
        user.setFailedAttempts(0);
        return user;
    }

    public Optional<Users> getByUserName(String userName) {
        return Optional.ofNullable(userStore.get(userName.toLowerCase()));
    }

    public void updateUser(Users user) {
        userStore.put(user.getUsername().toLowerCase(), user);
    }
}
	

