package org.mota.jwtdemo.configuration.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import static org.mota.jwtdemo.utils.JwtUtils.generateRefreshToken;
import static org.mota.jwtdemo.utils.JwtUtils.generateToken;

@Component
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final SecurityContextRepository securityContextRepository;
  private final ObjectMapper defaultObjectMapper;


  public JWTAuthenticationFilter(AuthenticationManager authenticationManager,
                                 SecurityContextRepository securityContextRepository,
                                 ObjectMapper defaultObjectMapper) {
    super(authenticationManager);
    this.authenticationManager = authenticationManager;
    this.securityContextRepository = securityContextRepository;
    this.defaultObjectMapper = defaultObjectMapper;
  }

  @Override
  @SneakyThrows
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    var jsonNode = defaultObjectMapper.readTree(request.getReader());
    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(
                jsonNode.get("login").textValue(),
                jsonNode.get("password").textValue());
    return authenticationManager.authenticate(authentication);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authentication) throws IOException {

    var userDetails = (UserDetails) authentication.getPrincipal();
    var accessToken = generateToken(userDetails);
    var authenticationWithCredentials = new UsernamePasswordAuthenticationToken(userDetails, accessToken, userDetails.getAuthorities());

    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authenticationWithCredentials);
    SecurityContextHolder.setContext(context);
    securityContextRepository.saveContext(context, request, response);
    authenticationWithCredentials.eraseCredentials();

    Map<String, String> tokens = new HashMap<>();
    tokens.put("token", accessToken);
    tokens.put("refresh_token", generateRefreshToken(userDetails));
    new ObjectMapper().writeValue(response.getOutputStream(), tokens);
  }
}
