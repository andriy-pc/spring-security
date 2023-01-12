package org.mota.jwtdemo.controller.filter;

import static java.util.Objects.isNull;
import static org.mota.jwtdemo.utils.JwtUtils.extractUsername;
import static org.mota.jwtdemo.utils.JwtUtils.validateToken;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.service.UserService;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

  private final UserService userService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().contains("/login")) {
      filterChain.doFilter(request, response);
      return;
    }
    String authorizationHeader = request.getHeader("Authorization");
    if (isNull(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
      throw new AuthorizationServiceException(
          "Authorization header is missing or incorrect (it should start with \"Bearer \")");
    }
    String token = authorizationHeader.split(" ")[1];
    UserDetails userDetails = userService.loadUserByUsername(extractUsername(token));
    Boolean isTokenValid = validateToken(token, userDetails);

    if (!isTokenValid) {
      throw new AuthorizationServiceException("Authorization token is invalid");
    }

    SecurityContextHolder.getContext()
        .setAuthentication(new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
            null,
            userDetails.getAuthorities()));

    filterChain.doFilter(request, response);
  }
}
