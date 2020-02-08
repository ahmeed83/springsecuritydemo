package com.focuesit.springsecuritydemo.auth;

import java.util.Optional;

public interface ApplicationUserDao {
  Optional<ApplicationUser> selectAppUserByUserName(String userName);
}
