package org.mota.jwtdemo.dao;

import java.util.Set;
import org.mota.jwtdemo.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleDao extends JpaRepository<Role, Integer> {

  Set<Role> findAllByNameIn(Set<String> name);

}
