package org.mota.jwtdemo.configuration.filter;

import static java.util.Objects.isNull;
import static org.mota.jwtdemo.utils.SecurityUtils.extractAccessToken;
import static org.mota.jwtdemo.utils.ServletUtils.setResponseStatus;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.service.JwtService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JWTAuthorizationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().contains("/sign-in")
        || request.getServletPath().contains("/register")) {
      filterChain.doFilter(request, response);
      return;
    }
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (isNull(authentication)
          || isNull(authentication.getPrincipal())
          || authentication.getPrincipal().equals("anonymousUser")) {
      setResponseStatus(response, UNAUTHORIZED, "You are not authorized to access this resource");
      return;
    }

    boolean isTokenValid = jwtService.isTokenValid(extractAccessToken(request), authentication);

    if (!isTokenValid) {
      throw new AccessDeniedException("Authorization token is invalid");
    }

    filterChain.doFilter(request, response);
  }
}
