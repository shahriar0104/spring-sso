package com.himanshuntwk.springoauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  @Order(1)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(Customizer.withDefaults());
    http
        .exceptionHandling((exceptions) -> exceptions
            .defaultAuthenticationEntryPointFor(
                //To customize the login page
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        .oauth2ResourceServer((resourceServer) -> resourceServer
            .jwt(Customizer.withDefaults()));

    System.out.println("SecurityFilterChain configured");

    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated()
        )
        .formLogin(Customizer.withDefaults());

    System.out.println("SecurityFilterChain configured 2");

    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of("http://ieims.local:3004")); // Adjust your allowed origins
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setAllowCredentials(true);

    // Optionally set allowed exposed headers, max age, etc.
    // configuration.setExposedHeaders(List.of("Authorization"));
    // configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);

    return source;
  }

  @Bean
  public WebMvcConfigurer corsConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/userinfo")
            .allowedOrigins("http://ieims.local:3004")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .allowCredentials(true);

        registry.addMapping("/**")
            .allowedOrigins("http://ieims.local:3004")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .allowCredentials(true);
        System.out.println("CORS configuration applied");
      }
    };
  }

  @Bean
  public TokenSettings tokenSettings() {
    return TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofHours(1))
        .refreshTokenTimeToLive(Duration.ofDays(1))
        .build();
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    return (context) -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        ArrayList<String> roles = new ArrayList<>();
        roles.add("BOARD_OFFICIAL");
        roles.add("BOARD_ADMIN");

        context.getClaims().claims((claims) -> {
          claims.put("boardCode", "DEB");
          claims.put("userStatus", "ACTIVE");
          claims.put("eiin", "108277");
//          claims.put("roles", roles);

          Map<String, List<String>> roleMap = new HashMap<>();
          roleMap.put("roles", roles);

          claims.put("realm_access", roleMap);
        });
      }
    };
  }

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
