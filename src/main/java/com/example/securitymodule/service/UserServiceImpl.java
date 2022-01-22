package com.example.securitymodule.service;

import com.example.securitymodule.domain.User;
import com.example.securitymodule.domain.UserPrincipal;
import com.example.securitymodule.enumeration.Role;
import com.example.securitymodule.exception.domain.EmailExistsException;
import com.example.securitymodule.exception.domain.UserNotFoundException;
import com.example.securitymodule.exception.domain.UsernameExistsException;
import com.example.securitymodule.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

import static com.example.securitymodule.constant.UserImplConstant.*;

@Service
@Transactional
@Qualifier("userDetailsService")
@AllArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findUserByUsername(username);

        if(user == null) {
            log.error(NO_USER_FOUND_BY_USERNAME + username);
            throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        } else {
          user.setLastLoginDateDisplay(user.getLastLoginDate());
          user.setLastLoginDate(new Date());
          userRepository.save(user);

          UserPrincipal userPrincipal = new UserPrincipal(user);
          log.info(USER_FOUND_BY_USERNAME + username);

          return userPrincipal;
        }
    }

    @Override
    public User register(String firstName, String lastName, String username, String email)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException {

        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);

        String password = generatePassword();
        String encodedPassword = encodePassword(password);

        User user = User.builder()
                .userId(generateUserId())
                .firstName(firstName)
                .lastName(lastName)
                .username(username)
                .email(email)
                .joinDate(new Date())
                .password(encodedPassword)
                .isActive(true)
                .isNotLocked(true)
                .role(Role.ROLE_USER.name())
                .authorities(Role.ROLE_USER.getAuthorities())
                .profileImageUrl(getTemporaryProfileImageUrl())
                .build();

        userRepository.save(user);

        log.info("New user password: " + password);
        return user;
    }

    private String getTemporaryProfileImageUrl() {
        return ServletUriComponentsBuilder // This takes the current path and adds an uri component.
                .fromCurrentContextPath()
                .path(DEFAULT_USER_IMAGE_PATH)
                .toUriString();
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String encodePassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    //  This validation method will be used for creating a new account AND updating a new account.
    private User validateNewUsernameAndEmail(String currentUsername,
                                             String newUsername,
                                             String newEmail) throws UserNotFoundException, UsernameExistsException, EmailExistsException {

        User userByNewUsername = findUserByUsername(newUsername);
        User userByNewEmail = findUserByEmail(newEmail);

        //  If "currentUsername" is blank, we're dealing with a new user, so we skip this part.
        if(StringUtils.isNotBlank(currentUsername)){

            User currentUser = findUserByUsername(currentUsername);

            if(currentUser == null){
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUsername);
            }

            if(userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())){
                throw new UsernameExistsException(THIS_USERNAME_ALREADY_EXISTS);
            }

            if(userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())){
                throw new EmailExistsException(THIS_EMAIL_ADDRESS_ALREADY_EXISTS);
            }

            return currentUser;
        } else{ // This is a new user. Now we make sure that email and username are not taken.

            if(userByNewUsername != null){
                throw new UsernameExistsException(THIS_USERNAME_ALREADY_EXISTS);
            }

            if(userByNewEmail != null){
                throw new EmailExistsException(THIS_EMAIL_ADDRESS_ALREADY_EXISTS);
            }

            return null;
        }
    }

    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }
}
