package com.cos.jwtserver.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도: JwtAuthenticationFilter");

        // 1. username, password 받아서

        // 2. 정상인지 로그인 시도를 해보는 거에요. authenticationManager로 로그인 시도를 하면!!
        // principalDetailsService가 실행이 된다. loadByUsername() 함수 실행됨.

        // 3. PrincipalDetails를 세션에 담고 (세션에 안담으면 권한관리가 안됨)

        // 4. JWT토큰을 만들어서 응답해주면 됨
        return super.attemptAuthentication(request, response);
    }
}
