package com.example.securitymodule.resource;

import com.example.securitymodule.constant.SecurityConstant;
import com.example.securitymodule.domain.HttpResponse;
import com.example.securitymodule.domain.User;
import com.example.securitymodule.domain.UserPrincipal;
import com.example.securitymodule.exception.domain.*;
import com.example.securitymodule.service.UserService;
import com.example.securitymodule.utility.JWTTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping({"/", "/user"}) // Use this mapping to ensure that the 404-page error handler will work properly.
@AllArgsConstructor
public class UserResource extends ExceptionHandling {

    public static final String EMAIL_WITH_THE_NEW_PASSWORD_WAS_SENT_TO = "An email with the new password was sent to: ";
    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTTokenProvider jwtTokenProvider;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, MessagingException {

        User newUser = userService.register(user.getFirstName(), user.getLastName(),
                                            user.getUsername(), user.getEmail());

        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {

        authenticate(user.getUsername(), user.getPassword());

        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);

        return new ResponseEntity<>(loginUser, jwtHeader, HttpStatus.OK);
    }

    @PostMapping("/add")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNotLocked") String isNotLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException {

        User newUser = userService.addNewUser(firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNotLocked), profileImage);

        return new ResponseEntity<>(newUser, HttpStatus.OK);
    }

    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam("currentUsername") String currentUsername,
                                           @RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNotLocked") String isNotLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException {

        User updatedUser = userService.update(currentUsername, firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNotLocked), profileImage);

        return new ResponseEntity<>(updatedUser, HttpStatus.OK);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username){

        User user = userService.findUserByUsername(username);
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers(){

        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email)
            throws EmailNotFoundException, MessagingException {

        userService.resetPassword(email);
        return response(HttpStatus.OK, EMAIL_WITH_THE_NEW_PASSWORD_WAS_SENT_TO + email);
    }

    private ResponseEntity<HttpResponse> response(HttpStatus ok, String message) {
        return null;
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {

        HttpHeaders headers = new HttpHeaders();
        headers.add(SecurityConstant.JWT_ACCESS_TOKEN_HEADER, jwtTokenProvider.generateJwtAccessToken(userPrincipal));
        headers.add(SecurityConstant.JWT_REFRESH_TOKEN_HEADER, jwtTokenProvider.generateJwtRefreshToken(userPrincipal));

        return headers;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
