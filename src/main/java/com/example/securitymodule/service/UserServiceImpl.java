package com.example.securitymodule.service;

import com.example.securitymodule.domain.User;
import com.example.securitymodule.domain.UserPrincipal;
import com.example.securitymodule.enumeration.Role;
import com.example.securitymodule.exception.domain.*;
import com.example.securitymodule.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.mail.MessagingException;
import javax.transaction.Transactional;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Date;
import java.util.List;

import static com.example.securitymodule.constant.FileConstant.*;
import static com.example.securitymodule.constant.UserImplConstant.*;

@Service
@Transactional
@Qualifier("userDetailsService")
@AllArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private LoginAttemptService loginAttemptService;
    @Autowired
    private EmailService emailService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findUserByUsername(username);

        if(user == null) {
            log.error(NO_USER_FOUND_BY_USERNAME + username);
            throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        } else {
            validateLoginAttempt(user);
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
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, MessagingException, EmailNotValidException, UsernameNotValidException {

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
                .profileImageUrl(getTemporaryProfileImageUrl(username))
                .build();

        userRepository.save(user); // Save new User in the database.
        log.info("PASSWORD " + password);
//        emailService.sendNewPasswordEmail(firstName, password, email); // Send to User the password by email.
        return user;
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

    @Override
    public User addNewUser(String firstName, String lastName, String username,
                           String email, String role, boolean isNotLocked,
                           boolean isActive, MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        String password = generatePassword();
        String encodedPassword = encodePassword(password);

        User user = User.builder()
                .userId(generateUserId())
                .firstName(firstName)
                .lastName(lastName)
                .joinDate(new Date())
                .username(username)
                .email(email)
                .password(encodedPassword)
                .isActive(true)
                .isNotLocked(true)
                .role(getRoleEnumName(role).name())
                .authorities(getRoleEnumName(role).getAuthorities())
                .profileImageUrl(getTemporaryProfileImageUrl(username))
                .build();

        userRepository.save(user);
        saveProfileImage(user, profileImage);

        return user;
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName,
                           String newUsername, String newEmail, String newRole,
                           boolean isNotLocked, boolean isActive, MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        User currentUser = validateNewUsernameAndEmail(currentUsername, newUsername, newEmail);


        currentUser.setFirstName(newFirstName);
        currentUser.setLastName(newLastName);
        currentUser.setUsername(newUsername);
        currentUser.setEmail(newEmail);
        currentUser.setActive(true);
        currentUser.setNotLocked(true);
        currentUser.setRole(getRoleEnumName(newRole).name());
        currentUser.setAuthorities(getRoleEnumName(newRole).getAuthorities());

        userRepository.save(currentUser);
        saveProfileImage(currentUser, profileImage);

        return currentUser;
    }

    @Override
    public void deleteUser(long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void resetPassword(String email) throws EmailNotFoundException, MessagingException {

        User user = findUserByEmail(email);

        if(user == null){
            throw new EmailNotFoundException(NO_USER_FOUND_BY_EMAIL);
        }

        String password = generatePassword();
        user.setPassword(encodePassword(password));
        userRepository.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), password, user.getEmail());
    }

    @Override
    public User updateProfileImage(String username, MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        User user = validateNewUsernameAndEmail(username, null, null);

        saveProfileImage(user, profileImage);

        return user;
    }

    private void saveProfileImage(User user, MultipartFile profileImage) throws IOException {

        if(profileImage != null){
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();

            if(!Files.exists(userFolder)){
                Files.createDirectories(userFolder);
                log.info(DIRECTORY_CREATED + userFolder);
            }

            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(profileImage.getInputStream(), userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION),
                    StandardCopyOption.REPLACE_EXISTING);

            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
            log.info(FILE_SAVED_IN_FILE_SYSTEM + profileImage.getOriginalFilename());
        }
    }

    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder // This takes the current path and adds an uri component.
                .fromCurrentContextPath()
                .path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION)
                .toUriString();
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }

    private void validateLoginAttempt(User user) {
        if(user.isNotLocked()){
            if(loginAttemptService.hasExceededMaxAttempts(user.getUsername())){
                user.setNotLocked(false);
            } else{
                user.setNotLocked(true);
            }
        } else{
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    private String getTemporaryProfileImageUrl(String username) {
        return ServletUriComponentsBuilder // This takes the current path and adds an uri component.
                .fromCurrentContextPath()
                .path(DEFAULT_USER_IMAGE_PATH + FORWARD_SLASH + username)
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
                                             String newEmail)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, UsernameNotValidException, EmailNotValidException {

        User userByNewUsername = findUserByUsername(newUsername);
        User userByNewEmail = findUserByEmail(newEmail);

        if(newUsername instanceof String == false || newUsername.isBlank()){
            throw new UsernameNotValidException(USERNAME_NOT_VALID);
        }

        EmailValidator emailValidator = EmailValidator.getInstance();
        if(!emailValidator.isValid(newEmail)){
            throw new EmailNotValidException(EMAIL_NOT_VALID);
        }

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
}
