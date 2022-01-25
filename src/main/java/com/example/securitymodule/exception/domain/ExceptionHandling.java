package com.example.securitymodule.exception.domain;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.securitymodule.domain.HttpResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.persistence.NoResultException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Objects;


@RestControllerAdvice
@Slf4j
public class ExceptionHandling implements ErrorController {

    public static final String ACCOUNT_LOCKED = "Your account has been locked.";
    public static final String METHOD_IS_NOT_ALLOWED = "This request method is not allowed on this endpoint. Please send a '%s' request." ;
    public static final String INTERNAL_SERVER_ERROR_MSG = "An error occurred while processing the request.";
    public static final String INCORRECT_CREDENTIALS = "Username or password incorrect. Please try again.";
    public static final String ACCOUNT_DISABLED = "Your account has been disabled.";
    public static final String ERROR_PROCESSING_FILE = "Error occurred while processing file.";
    public static final String NOT_ENOUGH_PERMISSIONS = "You do not have enough permissions.";
    public static final String USERNAME_NOT_VALID = "Username not valid.";
    public static final String EMAIL_NOT_VALID = "Email not valid.";

    @RequestMapping("/error") // It will work only with the ErrorController Interface.
    public ResponseEntity<HttpResponse> pageNotFoundException(){
        return createHttpResponse(HttpStatus.NOT_FOUND, "Page not found.");
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST, ACCOUNT_DISABLED);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> badCredentialsException(){
        return createHttpResponse(HttpStatus.BAD_REQUEST, INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException(){
        return createHttpResponse(HttpStatus.FORBIDDEN, NOT_ENOUGH_PERMISSIONS);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> lockedException(){
        return createHttpResponse(HttpStatus.UNAUTHORIZED, ACCOUNT_LOCKED);
    }

    @ExceptionHandler(UsernameNotValidException.class)
    public ResponseEntity<HttpResponse> usernameNotValidException(UsernameNotValidException exception){
        return createHttpResponse(HttpStatus.NOT_ACCEPTABLE, USERNAME_NOT_VALID);
    }

    @ExceptionHandler(EmailNotValidException.class)
    public ResponseEntity<HttpResponse> emailNotValidException(EmailNotValidException exception){
        return createHttpResponse(HttpStatus.NOT_ACCEPTABLE, EMAIL_NOT_VALID);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.UNAUTHORIZED, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(EmailExistsException.class)
    public ResponseEntity<HttpResponse> emailExistsException(EmailExistsException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(UsernameExistsException.class)
    public ResponseEntity<HttpResponse> usernameExistsException(UsernameExistsException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<HttpResponse> emailNotFoundException(EmailNotFoundException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<HttpResponse> userNotFoundException(UserNotFoundException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.BAD_REQUEST, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<HttpResponse> methodNotAllowedException(HttpRequestMethodNotSupportedException exception){
        log.error(exception.getMessage());
        HttpMethod supportedMethod = Objects
                .requireNonNull(exception.getSupportedHttpMethods())
                .iterator().next(); // The set will contain only one element, because all of our endpoints will have only one method.
        return createHttpResponse(HttpStatus.METHOD_NOT_ALLOWED, String.format(METHOD_IS_NOT_ALLOWED, supportedMethod));
    }

    //    For any other exception, which was not defined, we use this default exception handler.
    @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse> internalServerErrorException(Exception exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }

    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> noResultException(NoResultException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.NOT_FOUND, exception.getMessage().toUpperCase());
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<HttpResponse> noResultException(IOException exception){
        log.error(exception.getMessage());
        return createHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR, ERROR_PROCESSING_FILE);
    }

    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String message){

        HttpResponse httpResponse = new HttpResponse(
                httpStatus.value(),
                httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase());

        return new ResponseEntity<>(httpResponse,httpStatus);
    }
}
