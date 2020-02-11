package com.focuesit.springsecuritydemo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtTokenVerifier extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    String authorizationHeader = request.getHeader("Authorization");
    if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }
    final String token = authorizationHeader.replace("Bearer ", "");
    try {
      final String key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecure";
      final Jws<Claims> claimsJws = Jwts.parser()
          .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
          .parseClaimsJws(token);
      final Claims body = claimsJws.getBody();
      final String username = body.getSubject();  //sub
      final var authorities = (List<Map<String, String>>) body.get("authorities");
      final var simpleGrantedAuthorities =
          authorities.stream().map(m -> new SimpleGrantedAuthority(m.get("authority")))
              .collect(Collectors.toSet());
      Authentication authentication = new UsernamePasswordAuthenticationToken(
          username,
          null,
          simpleGrantedAuthorities
      );
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (JwtException e) {
      throw new IllegalStateException(String.format("Token can not be trusted!", token));
    }
    //Pass this filter to the next filter chain
    filterChain.doFilter(request, response);
  }
}
