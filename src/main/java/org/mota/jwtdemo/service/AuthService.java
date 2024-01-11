package org.mota.jwtdemo.service;

import static java.util.Collections.singleton;

import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.mota.jwtdemo.constants.RolesEnum;
import org.mota.jwtdemo.dto.UserDto;
import org.mota.jwtdemo.dto.UserLoginDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

  public static final Set<String> DEFAULT_USER_ROLE = singleton(RolesEnum.ROLE_USER.getName());
  private final AuthenticationManager authenticationManager;
  private final UserService userService;
  private final JwtService jwtService;

  private final ModelMapper modelMapper;

  @Transactional
  public UserLoginDto register(UserDto userDto) {
    //validation...
    userDto.setRoles(DEFAULT_USER_ROLE);
    UserDto savedUser = userService.save(userDto);
    return login(modelMapper.map(savedUser, UserLoginDto.class));
  }

  public UserLoginDto login(UserLoginDto userLoginDto) {
    UserDetails userDetails = userService.loadUserByUsername(userLoginDto.getLogin());
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(userDetails,
            userDetails.getPassword(),
            userDetails.getAuthorities()));

    return UserLoginDto.builder()
        .token(jwtService.generateToken(userDetails))
        .build();
  }

}
