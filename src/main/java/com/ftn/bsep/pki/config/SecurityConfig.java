package com.ftn.bsep.pki.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                  .requestMatchers("/api/auth/**").permitAll()
                  .requestMatchers("/api/admin/**").hasRole("ADMIN")
                  .requestMatchers("/api/ca/**").hasRole("CA_USER")
                  .requestMatchers("api/user/**").hasRole("END_USER")
                  .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.disable()); // CSRF se isključuje za testiranje REST API-ja

        return http.build();
    }

    @Bean
  public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
    }
}
