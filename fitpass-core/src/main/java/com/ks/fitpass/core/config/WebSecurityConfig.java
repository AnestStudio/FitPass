package com.ks.fitpass.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable) //http.csrf().disable();
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/css/**", "/images/**", "/js/**", "/webfonts/**").permitAll()
                .requestMatchers("/login", "/logout").permitAll()
                .requestMatchers("/vip/**").permitAll()
                .requestMatchers("/manage/**").hasRole("ADMIN")
                .requestMatchers("/statistics/chart", "/statistics/drink").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(formLogin -> formLogin
                // Submit URL login
                //.loginProcessingUrl("/j_spring_security_check")
                .loginPage("/login")
                .usernameParameter("account")
                .passwordParameter("password")
                .defaultSuccessUrl("/")
                .failureUrl("/login?error=true")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")                               // default url
                .logoutSuccessUrl("/login?logout")                  // default url
                .invalidateHttpSession(true)                        // default: true
                .deleteCookies("JSESSIONID")
            );
//            .httpBasic(withDefaults())
//                .rememberMe((remember) -> remember.rememberMeServices(rememberMeServices)
//            );
        return http.build();
    }

//    @Bean
//    RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
//        TokenBasedRememberMeServices.RememberMeTokenAlgorithm encodingAlgorithm = TokenBasedRememberMeServices.RememberMeTokenAlgorithm.SHA256;
//        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices("uniqueAndSecret", userDetailsService, encodingAlgorithm);
//        rememberMe.setMatchingAlgorithm(TokenBasedRememberMeServices.RememberMeTokenAlgorithm.MD5);
//        return rememberMe;
//    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        // Save remember me in memory (RAM)
        return new InMemoryTokenRepositoryImpl();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
