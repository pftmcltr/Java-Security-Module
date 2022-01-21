package com.example.securitymodule.resource;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.securitymodule.exception.domain.EmailExistsException;
import com.example.securitymodule.exception.domain.ExceptionHandling;
import com.example.securitymodule.exception.domain.UserNotFoundException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.persistence.NoResultException;

@RestController
@RequestMapping({"/", "/user"}) // Use this mapping to ensure that the 404-page error handler will work properly.
public class UserResource extends ExceptionHandling {

    @GetMapping("/home")
    public String getUser() throws LockedException {
        throw new LockedException("Locked");
//        return "It works.";
    }
}
