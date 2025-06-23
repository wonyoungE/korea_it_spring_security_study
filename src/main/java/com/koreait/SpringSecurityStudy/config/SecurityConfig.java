package com.koreait.SpringSecurityStudy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    // corsConfigurationSource() 설정은 spring security에서
    // CORS(Cross-Origin Resource Sharing)를 처리하기 위한 설정
    // CORS
    // 브라우저가 보안상 다른 도메인의 리소스 요청을 제한하는 정책
    // 기본적으로 브라우저는 같은 출처(Same-Origin)만 허용한다.
    // 도메인 / 포트가 다르면 다른 출처로 인식
    @Bean   // 객체 생성
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        // 요청을 보내는 쪽의 도메인(사이트 주소)을 허용할 것임.. ALL -> 모든 도메인 허용
        corsConfiguration.addAllowedOriginPattern(CorsConfiguration.ALL);
        // 요청을 보내는 쪽에서 Request, Response Header 정보에 대한 제약을 허용
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        // 요청을 보내는 쪽의 메서드(GET, POST, PUT, DELETE, OPTION, ..) 모두 허용
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);

        // 요청 URL에 대한 CORS 설정 적용을 위해 객체 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 URL(/**)에 대해 위에서 설정한 CORS 정책 적용
        source.registerCorsConfiguration("/**", corsConfiguration);
        // return 타입이 다른데..? -> UrlBased어쩌구가 corsConfigurationSource 구현한 것
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults()); // 위에서 만든 cors 설정을 security에 적용
        http.csrf(csrf -> csrf.disable());
        // CSRF란
        // 사용자가 의도하지 않은 요청을 공격자가 유도해서 서버에 전달하도록 하는 공격
        // JWT 방식 또는 무상태(Stateless) 인증이기 때문에
        // 세션이 없고, 쿠키도 안 쓰고, 토큰 기반이기 때문에 CSRF 공격 자체가 성립되지 않는다.

        // 서버사이드렌더링(SSR) 로그인 방식 비활성화
        http.formLogin(formLogin -> formLogin.disable());
        // HTTP 프로토콜 기본 로그인 방식 비활성화
        http.httpBasic(httpBasic -> httpBasic.disable());
        // 서버사이드렌더링(SSR) 로그아웃 비활성화
        http.logout(logout -> logout.disable());
        http.sessionManagement(Session -> Session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 사용 ㄴㄴ

        // 특정 요청 URL에 대한 권한 설정
        http.authorizeHttpRequests(auth -> {
            // requestMatchers()로 명시한 URL만 예외적으로 허용되거나 다른 권한을 부여할 수 있어.
            // 그 외의 모든 요청은 anyRequest()로 매핑돼서 기본 정책을 따름.
//            auth.requestMatchers("").permitAll();
            auth.anyRequest().authenticated(); // -> 로그인한(authenticated -> 인증된) 사용자만
        });

        return http.build();
    }
}
