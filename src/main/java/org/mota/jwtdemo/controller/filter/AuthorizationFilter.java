package org.mota.jwtdemo.controller.filter;

import static java.util.Objects.isNull;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.service.JwtService;
import org.mota.jwtdemo.service.UserService;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Profile("!oauth")
@Component
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

  private final UserService userService;
  private final JwtService jwtService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().contains("/login")
        || request.getServletPath().contains("/register")) {
      filterChain.doFilter(request, response);
      return;
    }
    String authorizationHeader = request.getHeader("Authorization");
    if (isNull(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
      throw new AccessDeniedException(
          "Authorization header is missing or incorrect (it should start with \"Bearer \")");
    }
    String token = authorizationHeader.split(" ")[1];
    UserDetails userDetails = userService.loadUserByUsername(jwtService.extractUsername(token));
    boolean isTokenValid = jwtService.isTokenValid(token, userDetails);

    if (!isTokenValid) {
      throw new AccessDeniedException("Authorization token is invalid");
    }

    SecurityContextHolder.getContext()
        .setAuthentication(new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
            null,
            userDetails.getAuthorities()));

    filterChain.doFilter(request, response);
  }
}
