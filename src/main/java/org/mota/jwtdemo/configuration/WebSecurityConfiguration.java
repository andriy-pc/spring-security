package org.mota.jwtdemo.configuration;

import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.controller.filter.AuthorizationFilter;
import org.mota.jwtdemo.controller.filter.JwtCreatingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

  private JwtCreatingFilter jwtCreatingFilter;
  private final AuthorizationFilter authorizationFilter;

  @Autowired
  @Lazy
  private void setJwtCreatingFilter(JwtCreatingFilter jwtCreatingFilter) {
    this.jwtCreatingFilter = jwtCreatingFilter;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests((authorize) ->
            authorize
                .requestMatchers("/auth/register").permitAll()
                .requestMatchers("/auth/login").permitAll()
                .requestMatchers("/users/details").access(authorityAuthorizationManager("USER"))
                .requestMatchers("/users/admin-details")
                .access(authorityAuthorizationManager("ADMIN"))
                .requestMatchers("/**").authenticated()
        )
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .headers().frameOptions()
        .sameOrigin()
        .and() //to display h2-console //TODO: enable this header only for h2-console EP
        .logout().and()
        .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilter(jwtCreatingFilter);

    return httpSecurity.build();
  }

  AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager(
      String... roles) {
    AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager =
        AuthorityAuthorizationManager.hasAnyRole(roles);
    authorityAuthorizationManager.setRoleHierarchy(roleHierarchy());
    return authorityAuthorizationManager;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
    return hierarchy;
  }
}
