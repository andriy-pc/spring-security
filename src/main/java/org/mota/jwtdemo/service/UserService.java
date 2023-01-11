package org.mota.jwtdemo.service;

import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.dao.UserDao;
import org.mota.jwtdemo.model.User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

  private final UserDao userDao;

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
}
