package com.example.securitymodule.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import static com.example.securitymodule.constant.SecurityConstant.*;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.securitymodule.domain.UserPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component // When the application starts, this will generate a JWTTokenProvider Bean.
public class JWTTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    //    Generate the JWT Access Token
    public String generateJwtAccessToken(UserPrincipal userPrincipal){

        String[] claims = getClaimsFromUser(userPrincipal);

        return JWT.create()
                .withIssuer(WEBSITE_NAME)
                .withAudience(WEBSITE_ADMINISTRATION)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES, claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));
    }

    //    Generate the JWT Refresh Token
    public String generateJwtRefreshToken(UserPrincipal userPrincipal){

        return JWT.create()
                .withIssuer(WEBSITE_NAME)
                .withAudience(WEBSITE_ADMINISTRATION)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));
    }

    //    Get the Authorities
    public List<GrantedAuthority> getAuthorities(String token){

        String[] claims = getClaimsFromToken(token);

        return Stream.of(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    //    Get Authentication
    public Authentication getAuthentication(String username,
                                            List<GrantedAuthority> authorities,
                                            HttpServletRequest request){

        UsernamePasswordAuthenticationToken usernamePasswordToken =
                new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        authorities);

        usernamePasswordToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        return usernamePasswordToken;
    }

    //    Validate Token
    public boolean isTokenValid(String username, String token){

        JWTVerifier verifier = getJWTVerifier();

        return StringUtils.isNotEmpty(username) && !isTokenExpired(verifier, token); // Use Commons Lang3 Library for strings.
    }

    //    Check Token's Expiration Date
    private boolean isTokenExpired(JWTVerifier verifier, String token) {

        Date expiration = verifier.verify(token).getExpiresAt();

        return expiration.before(new Date());
    }

    //    Get Subject
    public String getSubject(String token){

        JWTVerifier verifier = getJWTVerifier();

        return verifier.verify(token).getSubject();
    }

    private JWTVerifier getJWTVerifier() {

        JWTVerifier verifier;

        try{
            Algorithm algorithm = Algorithm.HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(WEBSITE_NAME).build();
        } catch (JWTVerificationException exception){ // Do not use this "exception" when sending errors to the user.
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }

        return  verifier;
    }

    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {

        List<String> authorities = new ArrayList<>();

        for(GrantedAuthority grantedAuthority : userPrincipal.getAuthorities()){
            authorities.add(grantedAuthority.getAuthority());
        }

        return authorities.toArray(new String[0]);
    }

    private String[] getClaimsFromToken(String token) {

        JWTVerifier verifier = getJWTVerifier();

        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }
}
