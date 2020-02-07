package com.focuesit.springsecuritydemo.security;

import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMIN;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.STUDENT;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
//needed only for @PreAuthorize
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
//        .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//        .and()
//        .csrf().disable() -> Cross site script forgery
        .authorizeRequests()
//        antMatchers -> THE ORDER MATTERS!!!
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
//        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.getRole(), ADMINTRAINEE.getRole())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {

    final UserDetails ahmedUser = User.builder()
        .username("ahmed")
        .password(passwordEncoder.encode("password"))
//        .roles(STUDENT.name()) // ROLE_STUDENT
        .authorities(STUDENT.getGrantedAuthority())
        .build();

    final UserDetails nassarUser = User.builder()
        .username("nassar")
        .password(passwordEncoder.encode("password123"))
//        .roles(ADMINTRAINEE.name()) // ROLE_ADMIN_TRAINEE
        .authorities(ADMINTRAINEE.getGrantedAuthority())
        .build();

    final UserDetails hayderUser = User.builder()
        .username("hayder")
        .password(passwordEncoder.encode("password123"))
//        .roles(ADMIN.name()) // ROLE_ADMIN
        .authorities(ADMIN.getGrantedAuthority())
        .build();

    return new InMemoryUserDetailsManager(hayderUser, nassarUser, ahmedUser);
  }
}
