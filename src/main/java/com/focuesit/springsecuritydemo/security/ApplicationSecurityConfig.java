package com.focuesit.springsecuritydemo.security;

import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMIN;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .anyRequest()
        .authenticated()
        .and()
        .formLogin()
        .loginPage("/login")
        .permitAll()
        .defaultSuccessUrl("/courses", true)
        .passwordParameter("password")
        .usernameParameter("username")
        .and()
        .rememberMe()
        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//        .key("somethingverysecured")
        .rememberMeParameter("remember-me")
        .and()
        .logout()
        .logoutUrl("/logout")
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout",
            "GET")) // https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/apidocs/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html
        .clearAuthentication(true)
        .invalidateHttpSession(true)
        .deleteCookies("JSESSIONID", "remember-me")
        .logoutSuccessUrl("/login");
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {

    final UserDetails ahmedUser = User.builder()
        .username("ahmed")
        .password(passwordEncoder.encode("password"))
        .authorities(STUDENT.getGrantedAuthority())
        .build();

    final UserDetails nassarUser = User.builder()
        .username("nassar")
        .password(passwordEncoder.encode("password123"))
        .authorities(ADMINTRAINEE.getGrantedAuthority())
        .build();

    final UserDetails hayderUser = User.builder()
        .username("hayder")
        .password(passwordEncoder.encode("password123"))
        .authorities(ADMIN.getGrantedAuthority())
        .build();

    return new InMemoryUserDetailsManager(hayderUser, nassarUser, ahmedUser);
  }
}
