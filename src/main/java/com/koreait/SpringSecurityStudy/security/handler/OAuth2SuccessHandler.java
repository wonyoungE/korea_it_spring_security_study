package com.koreait.SpringSecurityStudy.security.handler;

import com.koreait.SpringSecurityStudy.entity.OAuth2User;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.OAuth2UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    private OAuth2UserRepository oAuth2UserRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 구글 로그인하고 사용자 정보 파싱했을 때 어떻게 처리할지
        // OAuth2User 정보 가져오기, DefaultOAuth2User가 SecurityContextHolder에 들어가있는 인증 객체
        DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) authentication.getPrincipal();
        String provider = defaultOAuth2User.getAttribute("provider");
        String providerUserId = defaultOAuth2User.getAttribute("id");   // provider가 제공하는 id
        String email = defaultOAuth2User.getAttribute("email");

        // provider, providerUserId로 이미 연동된 사용자 정보가 있는지 DB 조회
        // 있으면 -> 연동 된 사람
        // 없으면 -> 연동 x -> 기존 회원인데 연동 안함 or 회원이 아닌 사람
        OAuth2User oAuth2User = oAuth2UserRepository.getOAuth2UserByProviderAndProviderUserId(provider, providerUserId);

        // OAuth2 로그인을 통해 회원가입이 되어있지 않거나 연동되지 않은 상태면
        if(oAuth2User == null) {
            //프론트로 provider와 providerUserId, email 전달
            response.sendRedirect("http://localhost:3000/auth/oauth2?provider=" + provider + "&providerUserId=" + providerUserId + "&email=" + email);
            return;
        }

        // 연동된 사용자가 있다면? => userId를 통해 회원 정보 조회
        Optional<User> optionalUser = userRepository.getUserByUserId(oAuth2User.getUserId());

        // OAuth2 로그인을 통해 회원가입이나 연동을 진행한 사용자인 경우 -> 사용자에게 토큰 발급
        String accessToken = null;
        if(optionalUser.isPresent()) {
            // generateAccessToken의 매개변수 -> String id
            // 여기서 id는 provider가 제공하는 id 아님
            accessToken = jwtUtil.generateAccessToken(Integer.toString(optionalUser.get().getUserId()));
        }

        // 최종적으로 accessToken을 쿼리 파라미터로 프론트에 전달
        response.sendRedirect("http://localhost:3000/auth/oauth2/signin?accessToken=" + accessToken);
        // 프론트에서 accessToken을 받아서 로컬 스토리지에 저장
        // 컨트롤러로 도착하기 전에 다 처리됨
    }
}
