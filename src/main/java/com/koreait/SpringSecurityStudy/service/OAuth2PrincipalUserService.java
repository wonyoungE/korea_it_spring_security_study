package com.koreait.SpringSecurityStudy.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

// spring security에서 기본으로 제공하는 OAuth2UserService를 상속받아 커스텀
@Service
public class OAuth2PrincipalUserService extends DefaultOAuth2UserService {

    // OAuth2 로그인 성공 시 호출되는 메서드
    // 로그인에 성공하면 구글이 Spring 서버에 ** 인가 코드(Authorization code) ** 를 제공함
    // 그러면 Spring 서버는 인가 코드를 가지고 구글에 다시 요청해서 >AccessToken + 사용자 정보< 받음
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // Spring Security가 OAuth2 Provider(구글, 카카오, 네이버, ...)에게 AccessToken으로 사용자 정보를 요청
        // 그 결과로 받은 사용자 정보(JSON)를 파싱한 객체를 리턴받음
        // userRequest 안에는 ClientRegistration, AccessToken, Additional Parameters가 있음
        // userRequest = 로그인 요청에 대한 정보 + access token
        // super.loadUser(...) = access token으로 사용자 정보를 요청
        // 최종적으로 → 이메일, 닉네임, 프로필 등 담긴 OAuth2User 객체가 나옴
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 사용자 정보(Map 형태) 추출
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // 어떤 OAuth2 Provider인지 확인
        // provider => 공급처 (google, naver, kakao, ...)
        String provider = userRequest.getClientRegistration().getRegistrationId();

        // 로그인한 사용자의 식별자(id), 이메일
        // provider마다 담아둔 곳이 다르다 => switch문 사용
        // 로그인 시 사용한 이메일
        String email = null;
        // provider에서 발행한 사용자 식별자
        String id = null;

        // provider 종류에 따라 사용자 정보 파싱 방식이 다르므로 분기 처리
        switch (provider) {
            case "google":
                id = attributes.get("sub").toString();
                email = (String) attributes.get("email");
                break;
        }

        // 우리가 필요한 정보만 골라서 새롭게 attributes 구성
        Map<String, Object> newAttributes = Map.of(
                    "id", id,
                    "provider", provider,
                    "email", email
        );

        // 권한 설정 => 임시 권한 부여 (ROLE_TEMPORARY)
        // 실제 권한은 OAuth2SuccessHandler에서 판단 (ㄹㅇ 일반 사용자도 임시 사용자가 되면 안되기 때문에)
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(("ROLE_TEMPORARY")));

        // Spring Security가 사용할 OAuth2User 객체 생성해서 반환
        // id => principal.getName()으로 가져올 때 사용됨
        // SecurityContextHolder에 DefaultOAuth2User가 인증 객체로 들어감
        return new DefaultOAuth2User(authorities, newAttributes, "id");
    }
}