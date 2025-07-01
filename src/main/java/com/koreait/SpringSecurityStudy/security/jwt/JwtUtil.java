package com.koreait.SpringSecurityStudy.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    private final Key KEY;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    // 액세스 토큰 만드는 메서드
    // 사용자의 id를 받아서 JWT 생성
    public String generateAccessToken(String id) {
            // 각 구성 요소는 JWT 3개 파트 중 어디?
            // Header -> 어떤 알고리즘으로 서명했는지 (signWith(KEY))
            // Payload -> subject, id, expiration
            // Signature -> Header + Payload를 비밀키(KEY)로 서명한 것
            return Jwts.builder()
                    .subject("AccessToken") // 토큰의 용도를 설명하는 식별자 역할
                    .id(id) // 토큰의 고유한 식별자 부여(사용자 ID, 이메일) => 나중에 토큰 무효화나 사용자 조회 시 사용
                    .expiration(new Date(new Date().getTime() + (1000L * 60L * 60L * 24L * 30L))) // 토큰의 만료 기간
                    // 현재 시간 기준으로 30일 뒤까지 유효
                    // 1000L -> 밀리초(=1초) 60L -> 60초(=1분) 60L -> 60분(=1시간) 24L -> 24시간(=1일) 30L -> 30일
                    .signWith(KEY) // 토큰에 서명을 적용 => 비밀키로 서명, 위변조 방지
                    .compact(); // 설정한 JWT 내용을 바탕으로 최종적으로 문자열 형태의 JWT 생성
    }

    // 메일 인증에 사용할 토큰 생성
    public String generateMailVerifyToken(String id) {
        return Jwts.builder()
                .subject("VerifyToken")
                .id(id)
                // 3분
                .expiration(new Date(new Date().getTime() + (1000L * 60L * 3L)))
                .signWith(KEY)
                .compact();
    }

    // 토큰이 맞는지 확인하는 메서드
    public boolean isBearer(String token) {
        if(token == null) {
            return false;
        }
        if(!token.startsWith("Bearer ")) {
            return false;
        }
        return true;
    }

    // 토큰에서 Bearer를 떼는 메서드
    public String removeBearer(String bearerToken) {
        return bearerToken.replaceFirst("Bearer ", "");
    }

    // Claims : JWT의 payload 영역, 사용자 정보, 만료일자 등 담겨 있음
    // JwtException: 토큰이 잘못되어있을 경우 (위변조, 만료) 발생하는 예외
    // 클라이언트가 보낸 JWT 토큰 검증하고 정보 꺼내는 메서드 - 토큰의 유효성(변조, 만료 여부) 확인
    public Claims getClaims(String token) throws JwtException {
        // 파싱이란? 문자열을 분석해서 의미 있는 데이터로 변환하는 것
        JwtParserBuilder jwtParserBuilder = Jwts.parser();  // (1) 파서 빌더 생성
        // Jwts.parser()는 JwtParserBuilder 객체를 반환
        // JWT 파서를 구성할 수 있는 빌더 (parser 설정 작업을 체이닝으로 가능하게 함)
        jwtParserBuilder.setSigningKey(KEY);    // (2) 서명 검증용 비밀키 설정, signature 검증 준비해라~
        JwtParser jwtParser = jwtParserBuilder.build(); // 설정이 완료된 파서를 빌드해서 최종 JwtParser 객체 생성
        // return 부분에서 모든 검증 + 예외 발생
        return jwtParser.parseClaimsJws(token).getBody();   // 순수 Claims JWT를 파싱
    }
}
