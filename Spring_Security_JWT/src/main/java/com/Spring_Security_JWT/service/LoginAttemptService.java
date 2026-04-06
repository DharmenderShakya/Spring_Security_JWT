package com.Spring_Security_JWT.service;

public interface LoginAttemptService {
	 void loginSucceeded(String username);
	 void loginFailed(String username);
}
