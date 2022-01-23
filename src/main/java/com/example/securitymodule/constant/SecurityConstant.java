package com.example.securitymodule.constant;

public class SecurityConstant {

    public static final long ACCESS_EXPIRATION_TIME = 1 * 24 * 60 * 60 * 1000; // 1 day
    public static final long REFRESH_EXPIRATION_TIME = 5 * 24 * 60 * 60 * 1000; // 5 days
    public static final String TOKEN_PREFIX = "Bearer "; // leave a space between Bearer and Token
    public static final String JWT_ACCESS_TOKEN_HEADER = "Access Token";
    public static final String JWT_REFRESH_TOKEN_HEADER = "Refresh Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String WEBSITE_NAME = "Jerry Hello";
    public static final String WEBSITE_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "Authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page.";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page.";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
//    public static final String[] PUBLIC_URLS = {"/user/login", "/user/register",
//                                                "/user/resetpassword/**", "user/image/**"};

    public static final String[] PUBLIC_URLS = {"**"}; // Allow all URLs (for testing purposes).
}
