package com.example.securitymodule.service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private static final int MAXIMUM_ATTEMPTS_ALLOWED = 5;
    private static final int ATTEMPT_INCREMENT = 1;
    private LoadingCache<String, Integer> loginAttemptCache;

    //    Initialize Cache from Guava Dependency
    public LoginAttemptService() {
        super();
        loginAttemptCache = CacheBuilder
                            .newBuilder()
                            .expireAfterWrite(15, TimeUnit.MINUTES)
                            .maximumSize(100)
                            .build(new CacheLoader<String, Integer>() {
                                @Override
                                public Integer load(String s) {
                                    return 0;
                                }
                            });
    }

    public void evictUserFromLoginAttemptCache(String username){
        loginAttemptCache.invalidate(username); // Remove user from cache.
    }

    public void addUserToLoginAttemptCache(String username) throws ExecutionException {

        int attempts = 0;

        attempts = ATTEMPT_INCREMENT + loginAttemptCache.get(username); // Before adding the user, add +1 to login attempts.
        loginAttemptCache.put(username, attempts); // Adding user to cache.
    }

    public boolean hasExceededMaxAttempts(String username) throws ExecutionException {
        return loginAttemptCache.get(username) >= MAXIMUM_ATTEMPTS_ALLOWED;
    }
}
