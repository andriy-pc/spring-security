package org.mota.jwtdemo.controller;

import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.dto.UserDto;
import org.mota.jwtdemo.dto.UserLoginDto;
import org.mota.jwtdemo.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/register")
  public ResponseEntity<UserLoginDto> register(@RequestBody UserDto userDto) {
    return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(userDto));
  }

  @PostMapping("/login")
  public ResponseEntity<UserLoginDto> login(@RequestBody UserLoginDto userLoginDto) {
    return ResponseEntity.ok().body(authService.login(userLoginDto));
  }

}
