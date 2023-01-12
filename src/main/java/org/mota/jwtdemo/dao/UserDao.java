package org.mota.jwtdemo.dao;

import java.util.List;
import java.util.Optional;
import org.mota.jwtdemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserDao extends JpaRepository<User, Integer> {

  Optional<User> findByLogin(String login);

  @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name IN (?1)")
  List<User> findByRoles(final List<String> roleNames);

}
