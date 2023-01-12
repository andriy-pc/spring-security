package org.mota.jwtdemo.constants;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum RolesEnum {

  ROLE_USER("ROLE_USER"),
  ROLE_ADMIN("ROLE_ADMIN");

  private final String name;

}
