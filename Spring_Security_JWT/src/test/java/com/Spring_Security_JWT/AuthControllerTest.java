package com.Spring_Security_JWT;


import com.Spring_Security_JWT.configuration.JWTUtils;
import com.Spring_Security_JWT.configuration.OurUserDetailsService;
import com.Spring_Security_JWT.controller.AuthController;
import com.Spring_Security_JWT.customRepository.UserCustomRepository;
import com.Spring_Security_JWT.entity.Users;
import com.Spring_Security_JWT.service.LoginAttemptService;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.security.test.context.support.WithMockUser;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JWTUtils jUtils;

    @MockBean
    private LoginAttemptService loService;

    @MockBean
    private UserCustomRepository userRepository;
    
    @MockBean
    private OurUserDetailsService ourUserDetailsService;
    
    @MockBean
    private com.Spring_Security_JWT.configuration.JwtAuthenticationFilter jwtAuthenticationFilter;

    @Test
    void testLoginSuccess() throws Exception {

        UserDetails userDetails = User.withUsername("test")
                .password("123")
                .roles("USER")
                .build();

        Authentication authentication = Mockito.mock(Authentication.class);

        Mockito.when(authenticationManager.authenticate(any()))
                .thenReturn(authentication);

        Mockito.when(authentication.getPrincipal())
                .thenReturn(userDetails);

        Mockito.when(jUtils.generateToken(userDetails))
                .thenReturn("mock-jwt-token");

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "userName":"test",
                                  "password":"123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(content().string("mock-jwt-token"));
    }

    @Test
    void testLoginFailure() throws Exception {

        Mockito.when(authenticationManager.authenticate(any()))
                .thenThrow(new RuntimeException("Bad credentials"));

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "userName":"wrong",
                                  "password":"wrong"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(content().string("Bad credentials"));
    }

    @Test
    void testCreateUser() throws Exception {

        mockMvc.perform(post("/auth/createUser")
                        .contentType("application/json")
                        .content("""
                                {
                                  "userName":"newUser",
                                  "password":"123"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(content().string("User Successfully created"));
    }


    @Test
    @WithMockUser(roles = "SUPER_ADMIN")
    void testUnlockAuthorized() throws Exception {

        Users user = new Users();
        user.setUserName("test");

        Mockito.when(userRepository.getByUserName("test"))
                .thenReturn(Optional.of(user));

        mockMvc.perform(put("/auth/unlock/test"))
                .andExpect(status().isOk())
                .andExpect(content().string("Account unlocked for test"));
    }

  
    @Test
    @WithMockUser(roles = "USER")
    void testUnlockUnauthorized() throws Exception {

        try {
            mockMvc.perform(put("/auth/unlock/test"));
        } catch (Exception e) {

            assertTrue(e.getCause() instanceof
                    org.springframework.security.authorization.AuthorizationDeniedException);
        }
    }

    @Test
    void testEndpoint() throws Exception {

        mockMvc.perform(get("/auth/test"))
                .andExpect(status().isOk())
                .andExpect(content().string("TEST WORKING"));
    }
    
}
