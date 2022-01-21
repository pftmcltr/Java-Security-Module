package com.example.securitymodule.filter;

import static com.example.securitymodule.constant.SecurityConstant.*;
import com.example.securitymodule.utility.JWTTokenProvider;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Component
@AllArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter { // This  will start only once, everytime there's a new request

    //  Token Provider
    private JWTTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {
        if(request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)){
            response.setStatus(HttpStatus.OK.value()); // If the request method is absent, we don't do anything
        } else{
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            if(authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX)){
                filterChain.doFilter(request, response); // Filter req & res if the header is null or does not include "Bearer"
                return; // We don't recognize the header, that's why we return nothing
            }
            String token = authorizationHeader.substring(TOKEN_PREFIX.length()); // Remove "Bearer" from token
            String username = jwtTokenProvider.getSubject(token); // Get the username
            if(jwtTokenProvider.isTokenValid(username,token) && // Check if token is valid
                    SecurityContextHolder.getContext().getAuthentication() == null){ // Check the context to see if the user is already authenticated
                List<GrantedAuthority> authorities = jwtTokenProvider.getAuthorities(token);
                Authentication authentication = jwtTokenProvider.getAuthentication(username, authorities, request);
                SecurityContextHolder.getContext().setAuthentication(authentication); // Authenticate the user
            } else{
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request,response);
    }
}
