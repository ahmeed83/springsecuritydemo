package com.focuesit.springsecuritydemo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

// This is the step 3 of JWT
// The client will send the token for every request and this filter will verify this token (OncePerRequestFilter)
// This filter will be executed once per request.
public class JwtTokenVerifier extends OncePerRequestFilter {

  private final JwtConfig jwtConfig;
  private final SecretKey secretKey;

  public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
    this.jwtConfig = jwtConfig;
    this.secretKey = secretKey;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    //First we take the Token form the request.
    String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
    if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
      filterChain.doFilter(request, response);
      //The request will be rejected!
      return;
    }
    //remove the Barer string
    final String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
    try {

      //get the signed token (dycrption)
      final Jws<Claims> claimsJws = Jwts.parser()
          .setSigningKey(secretKey)
          .parseClaimsJws(token);

      //get body
      final Claims body = claimsJws.getBody();

      //get the subject
      final String username = body.getSubject();

      // get the authorities
      final var authorities = (List<Map<String, String>>) body.get("authorities");
      final var simpleGrantedAuthorities =
          authorities.stream().map(m -> new SimpleGrantedAuthority(m.get("authority")))
              .collect(Collectors.toSet());

      //Get the authentication
      Authentication authentication = new UsernamePasswordAuthenticationToken(
          username,
          null,
          simpleGrantedAuthorities
      );

      // The clint who send the token is now authenticated!
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (JwtException e) {
      throw new IllegalStateException(String.format("Token can not be trusted!", token));
    }
    //Pass this filter to the next filter chain
    filterChain.doFilter(request, response);
  }
}
