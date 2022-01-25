package com.example.securitymodule.resource;

import com.example.securitymodule.constant.SecurityConstant;
import com.example.securitymodule.domain.HttpResponse;
import com.example.securitymodule.domain.User;
import com.example.securitymodule.domain.UserPrincipal;
import com.example.securitymodule.exception.domain.*;
import com.example.securitymodule.service.UserService;
import com.example.securitymodule.utility.JWTTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.example.securitymodule.constant.FileConstant.*;
import static com.example.securitymodule.constant.SecurityConstant.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping({"/", "/user"}) // Use this mapping to ensure that the 404-page error handler will work properly.
@AllArgsConstructor
@Slf4j
public class UserResource extends ExceptionHandling {

    public static final String EMAIL_WITH_THE_NEW_PASSWORD_WAS_SENT_TO = "An email with the new password was sent to: ";
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully.";

    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTTokenProvider jwtTokenProvider;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, MessagingException, EmailNotValidException, UsernameNotValidException {

        User newUser = userService.register(user.getFirstName(), user.getLastName(),
                                            user.getUsername(), user.getEmail());

        return ResponseEntity.ok().body(newUser);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {

        authenticate(user.getUsername(), user.getPassword());

        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        Map<String,String> tokens = getJwtTokens(userPrincipal);

        return ResponseEntity.ok().body(tokens);
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
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        User newUser = userService.addNewUser(firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNotLocked), profileImage);

        return ResponseEntity.ok().body(newUser);
    }

    @PostMapping("/update")
    public ResponseEntity<User> updateUser(@RequestParam("currentUsername") String currentUsername, // RequestParam comes from HTML Form data, so the value must be placed in the Body, not Paths.
                                           @RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNotLocked") String isNotLocked,
                                           @RequestParam(value = "profileImage", required = false) MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        User updatedUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role,
                Boolean.parseBoolean(isActive), Boolean.parseBoolean(isNotLocked), profileImage);

        return ResponseEntity.ok().body(updatedUser);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username){

        User user = userService.findUserByUsername(username);
        return ResponseEntity.ok().body(user);
    }

    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers(){

        List<User> users = userService.getUsers();
        return ResponseEntity.ok().body(users);
    }

    @GetMapping("/reset-password/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email)
            throws EmailNotFoundException, MessagingException {

        userService.resetPassword(email);
        return response(HttpStatus.OK, EMAIL_WITH_THE_NEW_PASSWORD_WAS_SENT_TO + email);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')") // Only users with "delete" authority can delete an account.
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("id") long id){

        userService.deleteUser(id);
        return response(HttpStatus.NO_CONTENT, USER_DELETED_SUCCESSFULLY);
    }

//    UPDATE PROFILE PICTURE
    @PostMapping("/update-profile-image")
    public ResponseEntity<User> updateProfileImage(@RequestParam("username") String username,
                                                   @RequestParam(value = "profileImage") MultipartFile profileImage)
            throws UserNotFoundException, UsernameExistsException, EmailExistsException, IOException, EmailNotValidException, UsernameNotValidException {

        User user = userService.updateProfileImage(username, profileImage);
        return ResponseEntity.ok().body(user);
    }

//    GET PROFILE PICTURE
    @GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username,
                                  @PathVariable("fileName") String fileName) throws IOException {

        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName)); // "user.home" + "/supportportal/user/username/username.jpg"
    }

//    ROBOHASH PROFILE PICTURE
    @GetMapping(path = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {

        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + FORWARD_SLASH + username); // Create a URL.
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(); // Store the data that comes from the URL.

        try(InputStream inputStream = url.openStream()){ // Open the URL.
            int bytesRead;
            byte[] chunk = new byte[1024]; // Read 1024 from the inputStream.
            while((bytesRead = inputStream.read(chunk)) > 0){ // Read chunks of inputStream until we're done.
                byteArrayOutputStream.write(chunk, 0, bytesRead); // Loop 1 - 1024 bytes, Loop 2 - 1024 bytes.
            }
        } catch (Exception exception){
            throw new IOException("Robohash did not generate the image.");
        }

        return byteArrayOutputStream.toByteArray();
    }

    @GetMapping("/token/refresh")
    public void tokenRefresh(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader != null || authorizationHeader.startsWith(TOKEN_PREFIX)){
                String refresh_token = authorizationHeader.substring(TOKEN_PREFIX.length()); // Remove "Bearer" from token.
                String username = jwtTokenProvider.getSubject(refresh_token); // Get the username.
                User user = userService.findUserByUsername(username);
                UserPrincipal userPrincipal = new UserPrincipal(user);
                String access_token = jwtTokenProvider.generateJwtAccessToken(userPrincipal);

                Map<String,String> tokens = new HashMap<>();
                tokens.put(JWT_ACCESS_TOKEN_HEADER, access_token);
                tokens.put(JWT_REFRESH_TOKEN_HEADER, refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
        } else{
            response.setHeader("Error", TOKEN_CANNOT_BE_VERIFIED);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            Map<String,String> error = new HashMap<>();
            error.put("Error", TOKEN_CANNOT_BE_VERIFIED);
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
    }

    /////////////////////////////////////////////

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {

        HttpResponse body = new HttpResponse(
                httpStatus.value(),
                httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase());

        return new ResponseEntity<>(body, httpStatus); // ResponseEntity takes two parameters: body & httpStatus. In this case, the body is the HttpResponse custom class.
    }

    private Map getJwtTokens(UserPrincipal userPrincipal) {

        Map<String,String> tokens = new HashMap<>();
        tokens.put(SecurityConstant.JWT_ACCESS_TOKEN_HEADER, jwtTokenProvider.generateJwtAccessToken(userPrincipal));
        tokens.put(SecurityConstant.JWT_REFRESH_TOKEN_HEADER, jwtTokenProvider.generateJwtRefreshToken(userPrincipal));

        return tokens;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
