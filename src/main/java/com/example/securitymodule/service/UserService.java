package com.example.securitymodule.service;

import com.example.securitymodule.domain.User;
import com.example.securitymodule.exception.domain.EmailExistsException;
import com.example.securitymodule.exception.domain.EmailNotFoundException;
import com.example.securitymodule.exception.domain.UserNotFoundException;
import com.example.securitymodule.exception.domain.UsernameExistsException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistsException, EmailExistsException, MessagingException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role,
                    boolean isNotLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername,
                    String newEmail, String newRole, boolean isNotLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException;

    void deleteUser(long id);

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;

    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException;

    User update(String currentUsername, String firstName, String lastName, String username, String email, String role, boolean parseBoolean, boolean parseBoolean1, MultipartFile profileImage);
}
