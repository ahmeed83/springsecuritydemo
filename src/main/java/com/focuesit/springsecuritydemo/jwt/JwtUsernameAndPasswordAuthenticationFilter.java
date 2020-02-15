package com.focuesit.springsecuritydemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// we extend one of the request filters to provide it with owr implementation (UsernamePasswordAuthenticationFilter)
//Filter are classes that preform some kind of validation before reaching the destination API
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final JwtConfig jwtConfig;
  private final SecretKey secretKey;

  public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                    JwtConfig jwtConfig,
                                                    SecretKey secretKey) {
    this.authenticationManager = authenticationManager;
    this.jwtConfig = jwtConfig;
    this.secretKey = secretKey;
  }

  // This method will do the first step in JWT when the user send its credentials and Spring
  // will validate those credentials
  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {
    try {
      // first we will put the inputStream of the request in the class that we made which
      // has only username and password
      final UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
          .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

      // generate an authentication to pass it in the AuthenticationManager method.
      Authentication authentication = new UsernamePasswordAuthenticationToken(
          authenticationRequest.getUsername(),
          authenticationRequest.getPassword()
      );
      // this method will check if the user exists and and also checks the password.
      return authenticationManager.authenticate(authentication);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  //This is the second step in JWT. Spring will send the Token back to the client
  //This method will be invoked after the attemptAuthentication will finish successfully
  //This method will generate a Token and send it back to the client.
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) {

    //The token consist of: Header/Payload/Signature

    final String token = Jwts.builder()

        // Subject of the token
        .setSubject(authResult.getName())

        // claim is where you specify the body of the TOKEN
        .claim("authorities", authResult.getAuthorities())
        .setIssuedAt(new Date())
        .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
        // example of a body :
        /*
        {
          "sub": "ahmed",
          "authorities": [{
            "authority": "ROLE_STUDENT"
          }],
          "iat": 1581761607,
          "exp": 1582930800
         }
        */
        // signWith is the Signature part of the TOKEN
        .signWith(secretKey)
        .compact();

    //And then send it back to the header of the client!
    response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
  }
}
