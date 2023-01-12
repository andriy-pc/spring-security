package org.mota.jwtdemo.controller;

import java.security.Principal;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.dto.UserDto;
import org.mota.jwtdemo.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserDetailsController {

  private final UserService userService;

  @GetMapping("/details")
  public ResponseEntity<List<UserDto>> getUserDetails(Principal principal) {
    return ResponseEntity.ok(userService.findByRoles(
        SecurityContextHolder.getContext().getAuthentication().getAuthorities()));
  }

  @GetMapping("/admin-details")
  public ResponseEntity<List<UserDto>> getAdminDetails() {
    return ResponseEntity.ok(userService.findByRoles(
        SecurityContextHolder.getContext().getAuthentication().getAuthorities()));
  }

  @GetMapping("/me")
  public ResponseEntity<UserDto> getCurrentUser() {
    return ResponseEntity.ok(userService.currentUserDetails());
  }

}
