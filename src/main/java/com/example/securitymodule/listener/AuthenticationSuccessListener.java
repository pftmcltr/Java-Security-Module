package com.example.securitymodule.listener;

import com.example.securitymodule.domain.User;
import com.example.securitymodule.domain.UserPrincipal;
import com.example.securitymodule.service.LoginAttemptService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class AuthenticationSuccessListener {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event){

        Object principal = event.getAuthentication().getPrincipal();

        if(principal instanceof UserPrincipal){
            UserPrincipal userPrincipal = (UserPrincipal) event.getAuthentication().getPrincipal();
            loginAttemptService.evictUserFromLoginAttemptCache(userPrincipal.getUsername());
        }
    }
}
