package org.mota.jwtdemo.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.mota.jwtdemo.dao.RoleDao;
import org.mota.jwtdemo.dao.UserDao;
import org.mota.jwtdemo.dto.UserDto;
import org.mota.jwtdemo.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

  private final UserDao userDao;
  private final RoleDao roleDao;
  private final ModelMapper modelMapper;

  @Override
  public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
    Optional<User> dbUser = userDao.findByLogin(login);
    if (dbUser.isEmpty()) {
      throw new UsernameNotFoundException("User was not found by login: " + login);
    }
    return new org.springframework.security.core.userdetails.User(
        dbUser.get().getLogin(),
        dbUser.get().getPassword(),
        dbUser.get().getRoles().stream()
            .map(role -> new SimpleGrantedAuthority(role.getName())).collect(
                Collectors.toList())
    );
  }

  @Transactional
  public UserDto save(UserDto userDto) {
    User toSave = modelMapper.map(userDto, User.class);
    toSave.setRoles(roleDao.findAllByNameIn(userDto.getRoles()));

    User saved = userDao.save(toSave);
    userDto.setId(saved.getId());
    return userDto;
  }

  public List<UserDto> findByRoles(Collection<? extends GrantedAuthority> roles) {
    List<User> users = userDao.findByRoles(
        roles.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

    return users.stream()
        .map(user -> modelMapper.map(user, UserDto.class))
        .collect(Collectors.toList());
  }

  public UserDto currentUserDetails() {
    String currentUserLogin = SecurityContextHolder.getContext().getAuthentication().getName();
    return modelMapper.map(userDao.findByLogin(currentUserLogin).get(), UserDto.class);
  }
}
