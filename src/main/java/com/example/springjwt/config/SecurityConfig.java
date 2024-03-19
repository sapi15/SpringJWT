package com.example.springjwt.config;

import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;

    //JWTUtil 주입
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));                // 허용 url
                configuration.setAllowedMethods(Collections.singletonList("*"));                                    // 모든 post,get,put,delete,patch 요청허용
                configuration.setAllowCredentials(true);                                                            // 내 서버가 응답할 때 json을 JS에서 처리할 수 있게 설정
                configuration.setAllowedHeaders(Collections.singletonList("*"));                                    // 모든 header에 응답 허용
                configuration.setMaxAge(3600L);                                                                     // 허용 시간?

                configuration.setExposedHeaders(Collections.singletonList("Authorization"));                        // Authorization 헤더 허용.(?)

                return configuration;
            }
        })));

        //csrf disable
        http.csrf((auth) -> auth.disable());            // JWT 방식에서는 필요 없는듯.

        //From 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());       // JWT 방식에서는 필요 없는듯.

        //http basic 인증 방식 disable
        http.httpBasic((auth) -> auth.disable());       // JWT 방식에서는 필요 없는듯.

        //경로별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //JWTFilter 등록, JWTFilter를 LoginFilter 앞에다 주입.
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        http.sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));           // JWT 방식에서는 세션을 STATELESS 상태로 관리된다고 함. (필수 설정.)


        return http.build();
    }


}
