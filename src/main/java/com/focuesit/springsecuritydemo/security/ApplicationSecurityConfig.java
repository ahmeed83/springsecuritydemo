package com.focuesit.springsecuritydemo.security;

import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.STUDENT;

import com.focuesit.springsecuritydemo.auth.ApplicationUserService;
import com.focuesit.springsecuritydemo.jwt.JwtConfig;
import com.focuesit.springsecuritydemo.jwt.JwtTokenVerifier;
import com.focuesit.springsecuritydemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import javax.crypto.SecretKey;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;
  private final ApplicationUserService applicationUserService;

  private final JwtConfig jwtConfig;
  private final SecretKey secretKey;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
      JwtConfig jwtConfig, SecretKey secretKey) {
    this.passwordEncoder = passwordEncoder;
    this.applicationUserService = applicationUserService;
    this.jwtConfig = jwtConfig;
    this.secretKey = secretKey;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        // Because we are using JWT then we need to make sure that the authentication is stateless
        // The session will not stores in the db anymore
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        //add filter to the filter chain for the JWT
        //add the authenticationManager() that we inherent form WebSecurityConfigurerAdapter
        // Add filter 1 authenticate the user - when he wants to login
        .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
        // Add filter 2 verify the user after each req
        .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .anyRequest()
        .authenticated();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider((daoAuthenticationProvider()));
  }

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserDetailsService(applicationUserService);
    return provider;
  }
}
