package com.example.securitymodule.listener;

import com.example.securitymodule.service.LoginAttemptService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class AuthenticationFailureListener {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event){

        Object principal = event.getAuthentication().getPrincipal();

        if(principal instanceof String){
            String username = (String) event.getAuthentication().getPrincipal(); // Double-check the principal.
            loginAttemptService.addUserToLoginAttemptCache(username);
        }
    }
}
