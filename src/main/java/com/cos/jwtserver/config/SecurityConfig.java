package com.cos.jwtserver.config;

import com.cos.jwtserver.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtserver.filter.MyFilter1;
import com.cos.jwtserver.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager =  http.getSharedObject(AuthenticationManager.class);

        // BasicAuthenticationFilter가 동작하기전에 MyFilter3이 동작한다.
        // After든 Before든 직접 만든 Filter보다는 똑같이 먼저 동작함
        // 스프링 시큐리티보다 먼저 동작하게 하려면 Before로 걸어라
//        http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);

        // 스프링 시큐리티 이전에 가장 빨리 동작하는 필터가 된다.
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf(CsrfConfigurer::disable);

        // 세션을 사용하지 않겠다.
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.addFilter(corsFilter); //@CrossOrigin(인증X), 시큐리티 필터에 등록 인증O
        // 폼태그로 로그인을 안하겠다.
        http.formLogin(form -> form.disable());
//        http.formLogin(form -> form.loginProcessingUrl("/login"));
        http.addFilter(new JwtAuthenticationFilter(authenticationManager)); // authenticationManager도 줘야함
        http.httpBasic(httpBasic -> httpBasic.disable());
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers("/api/v1/user/**")
                        .hasAnyRole("USER", "MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/manager/**")
                        .hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**")
                        .hasAnyRole("ADMIN")
                        .anyRequest().permitAll());


        return http.build();
    }
}