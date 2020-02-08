package com.focuesit.springsecuritydemo.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserService implements UserDetailsService {

  private final ApplicationUserDao applicationUserDao;

  @Autowired
  public ApplicationUserService(@Qualifier("fake") ApplicationUserDao applicationUserDao) {
    this.applicationUserDao = applicationUserDao;
  }

  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
    return applicationUserDao
        .selectAppUserByUserName(userName)
        .orElseThrow(() ->
            new UsernameNotFoundException(String.format("UserName %s not found", userName))
        );
  }
}
