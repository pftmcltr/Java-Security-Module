package com.example.securitymodule.exception.domain;

public class UsernameExistsException extends Exception{

    public UsernameExistsException(String message) {
        super(message);
    }
}
