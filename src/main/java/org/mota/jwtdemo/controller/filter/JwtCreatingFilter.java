package org.mota.jwtdemo.controller.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.mota.jwtdemo.service.UserService;
import org.mota.jwtdemo.utils.JwtUtils;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@Component
@Profile("jwt-old")
public class JwtCreatingFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final UserService userService;

  public JwtCreatingFilter(AuthenticationManager authenticationManager, UserService userService) {
    super(authenticationManager);
    this.authenticationManager = authenticationManager;
    this.userService = userService;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(
            request.getParameter("login"),
            request.getParameter("password"));
    return authenticationManager.authenticate(authentication);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException {
    UserDetails userDetails = userService.loadUserByUsername(request.getParameter("login"));
    Map<String, String> tokens = new HashMap<>();
    tokens.put("token", JwtUtils.generateToken(userDetails));
    tokens.put("refresh_token", JwtUtils.generateRefreshToken(userDetails));
    new ObjectMapper().writeValue(response.getOutputStream(), tokens);
  }
}
