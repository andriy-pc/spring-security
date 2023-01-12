package org.mota.jwtdemo.configuration;

import lombok.RequiredArgsConstructor;
import org.mota.jwtdemo.controller.filter.AuthorizationFilter;
import org.mota.jwtdemo.controller.filter.JwtCreatingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

  private final AuthenticationConfiguration authenticationConfiguration;
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
                .requestMatchers("/users/**").authenticated()
                .requestMatchers("/**").authenticated()
        )
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .headers().frameOptions()
        .sameOrigin().and() //to display h2-console //TODO: enable this header only for h2-console EP
        .logout().and()
        .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilter(jwtCreatingFilter);

    return httpSecurity.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public AuthenticationManager authenticationManager()
      throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

}
