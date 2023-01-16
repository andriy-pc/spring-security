package org.mota.jwtdemo.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.mota.jwtdemo.configuration.serialization.PasswordSerializer;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

  private Integer id;
  private String firstName;
  private String secondName;
  private String login;
  @JsonSerialize(using = PasswordSerializer.class)
  private String password;
  @JsonIgnore
  private Set<String> roles;

}
