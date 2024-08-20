package com.himanshuntwk.springoauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfig {

  @Bean
  UserDetailsService inMemoryUserDetailsManager() {
    var userBuilder = User.builder();
    UserDetails himanshu = userBuilder
        .username("admin")
        .password("admin")
        .roles("USER", "ADMIN")
        .build();
    return new InMemoryUserDetailsManager(himanshu);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}
