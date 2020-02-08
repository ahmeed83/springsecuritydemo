package com.focuesit.springsecuritydemo.auth;

import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMIN;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.focuesit.springsecuritydemo.security.ApplicationUserRole.STUDENT;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectAppUserByUserName(String userName) {
    return getApplicationUsers()
        .stream()
        .filter(applicationUser -> userName.equals(applicationUser.getUsername()))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUsers() {
    List<ApplicationUser> applicationUsers = Lists.newArrayList(
        new ApplicationUser(
            ADMIN.getGrantedAuthority(),
            passwordEncoder.encode("password"),
            "hayder",
            true,
            true,
            true,
            true
        ),
        new ApplicationUser(
            ADMINTRAINEE.getGrantedAuthority(),
            passwordEncoder.encode("password"),
            "nassar",
            true,
            true,
            true,
            true
        ),
        new ApplicationUser(
            STUDENT.getGrantedAuthority(),
            passwordEncoder.encode("password"),
            "ahmed",
            true,
            true,
            true,
            true
        )
    );
    return applicationUsers;
  }
}