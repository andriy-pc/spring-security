package org.mota.jwtdemo.configuration;

import static org.mota.jwtdemo.constants.RolesEnum.ROLE_ADMIN;
import static org.mota.jwtdemo.constants.RolesEnum.ROLE_USER;

import org.mota.jwtdemo.auth.AccessTokenRevokingLogoutHandler;
import org.mota.jwtdemo.configuration.filter.JWTAuthenticationFilter;
import org.mota.jwtdemo.configuration.filter.JWTAuthorizationFilter;
import org.mota.jwtdemo.auth.TokenBasedSecurityContextRepository;
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
public class WebSecurityConfiguration {

  private final JWTAuthorizationFilter jwtAuthorizationFilter;
  private final JWTAuthenticationFilter jwtAuthenticationFilter;

  public WebSecurityConfiguration(JWTAuthorizationFilter jwtAuthorizationFilter,
                                  @Lazy JWTAuthenticationFilter jwtAuthenticationFilter) {
    this.jwtAuthorizationFilter = jwtAuthorizationFilter;
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                         TokenBasedSecurityContextRepository tokenBasedSecurityContextRepository,
                                         AccessTokenRevokingLogoutHandler accessTokenRevokingLogoutHandler
  ) throws Exception {
    httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(authorize ->
            authorize
                .requestMatchers("/auth/register").permitAll()
                .requestMatchers("/sign-in").permitAll()
                .requestMatchers("/users/details")
                .access(authorityAuthorizationManager(ROLE_USER.getNameWithoutPrefix()))
                .requestMatchers("/users/admin-details")
                .access(authorityAuthorizationManager(ROLE_ADMIN.getNameWithoutPrefix()))
                .requestMatchers("/**").authenticated()
        )
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .securityContext(securityContext -> securityContext.securityContextRepository(tokenBasedSecurityContextRepository))
        .headers().frameOptions()
        .sameOrigin() //to display h2-console. enable this header only for h2-console EP
        .and()
        .addFilter(getAuthenticationFilter())
        .logout(logout -> logout.addLogoutHandler(accessTokenRevokingLogoutHandler))
        .addFilterBefore(jwtAuthorizationFilter,
            org.springframework.security.web.access.intercept.AuthorizationFilter.class);

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


  private UsernamePasswordAuthenticationFilter getAuthenticationFilter() {
    jwtAuthenticationFilter.setFilterProcessesUrl("/sign-in");
    return jwtAuthenticationFilter;
  }

  @Bean
  RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
    return hierarchy;
  }
}
