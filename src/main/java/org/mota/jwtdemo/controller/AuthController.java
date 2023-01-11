package org.mota.jwtdemo.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
//@RequestMapping
public class AuthController {

  @PostMapping("/login")
  public void login() {
    System.out.println("logging in");
  }

}
