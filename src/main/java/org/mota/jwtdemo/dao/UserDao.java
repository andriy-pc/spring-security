package org.mota.jwtdemo.dao;

import java.util.Optional;
import org.mota.jwtdemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User, Integer> {

  Optional<User> findByLogin(String login);

}
