package org.mota.jwtdemo;

import org.mota.jwtdemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.userdetails.UserDetails;

@SpringBootApplication
public class JwtDemoApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}

	@Autowired
	UserService userService;

	@Override
	public void run(String... args) throws Exception {
		UserDetails userDetails = userService.loadUserByUsername("doj");
		System.out.println(userDetails);
	}
}
