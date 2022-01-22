package com.example.securitymodule.service;

import com.example.securitymodule.domain.User;
import com.example.securitymodule.exception.domain.EmailExistsException;
import com.example.securitymodule.exception.domain.UserNotFoundException;
import com.example.securitymodule.exception.domain.UsernameExistsException;

import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistsException, EmailExistsException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

}
