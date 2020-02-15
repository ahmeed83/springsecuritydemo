package com.focuesit.springsecuritydemo.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

  private String secretKey;
  private String tokenPrefix;
  private int tokenExpirationAfterDays;

  @Bean
  public SecretKey secretKey() {
    return Keys.hmacShaKeyFor(secretKey.getBytes());
  }

  public String getAuthorizationHeader() {
    return HttpHeaders.AUTHORIZATION;
  }

  public void setSecretKey(String secretKey) {
    this.secretKey = secretKey;
  }

  public String getTokenPrefix() {
    return tokenPrefix;
  }

  public void setTokenPrefix(String tokenPrefix) {
    this.tokenPrefix = tokenPrefix;
  }

  public int getTokenExpirationAfterDays() {
    return tokenExpirationAfterDays;
  }

  public void setTokenExpirationAfterDays(int tokenExpirationAfterDays) {
    this.tokenExpirationAfterDays = tokenExpirationAfterDays;
  }
}