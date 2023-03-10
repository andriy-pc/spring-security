package org.mota.jwtdemo.configuration;

import org.modelmapper.ModelMapper;
import org.mota.jwtdemo.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CommonConfiguration {

  @Bean
  public ModelMapper modelMapper() {
    ModelMapper modelMapper = new ModelMapper();
    modelMapper.addConverter((context) -> {
      Role role = new Role();
      role.setName(context.getSource());
      return role;
    }, String.class, Role.class);
    return modelMapper;
  }

}
