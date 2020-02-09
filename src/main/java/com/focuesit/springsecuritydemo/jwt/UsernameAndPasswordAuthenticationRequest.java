package com.focuesit.springsecuritydemo.jwt;

public class UsernameAndPasswordAuthenticationRequest {

  private String userName;
  private String password;

  public UsernameAndPasswordAuthenticationRequest() {
  }

  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
