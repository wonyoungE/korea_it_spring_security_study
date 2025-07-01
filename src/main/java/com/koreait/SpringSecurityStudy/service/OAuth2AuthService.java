package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.dto.OAuth2MergeReqDto;
import com.koreait.SpringSecurityStudy.dto.OAuth2SignupReqDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.entity.UserRole;
import com.koreait.SpringSecurityStudy.repository.OAuth2UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class OAuth2AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private OAuth2UserRepository oAuth2UserRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public ApiRespDto<?> signup(OAuth2SignupReqDto oAuth2SignupReqDto) {
        // 해당 이메일이 가입되어 있는지 먼저 확인
        Optional<User> optionalUser = userRepository.getUserByEmail(oAuth2SignupReqDto.getEmail());

        if(optionalUser.isPresent()) {
            return new ApiRespDto<>("failed", "이미 가입된 이메일입니다.", null);
        }

        // userId 있는 user객체 반환
        Optional<User> user = userRepository.addUser(oAuth2SignupReqDto.toEntity(bCryptPasswordEncoder));

        // userRole 추가
        UserRole userRole = UserRole.builder()
                .userId(user.get().getUserId())
                .roleId(3)  // 임시 사용자 role
                .build();
        userRoleRepository.addUserRole(userRole);

        // OAuth2User 추가
        oAuth2UserRepository.insertOAuth2User(oAuth2SignupReqDto.toOAuth2User(user.get().getUserId()));

        return new ApiRespDto<>("success", "OAuth2 회원가입 완료", null);
    }

    // 소셜 로그인 연동 -> 회원가입은 되어있지만 소셜 등록은 안되어있는 회원
    public ApiRespDto<?> merge(OAuth2MergeReqDto oAuth2MergeReqDto) {
        Optional<User> optionalUser = userRepository.getUserByUsername(oAuth2MergeReqDto.getUsername());

        if(optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        if(!bCryptPasswordEncoder.matches(oAuth2MergeReqDto.getPassword(), optionalUser.get().getPassword())) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        oAuth2UserRepository.insertOAuth2User(oAuth2MergeReqDto.toOAuth2User(optionalUser.get().getUserId()));
        
        return new ApiRespDto<>("success", "회원가입이 완료되었습니다.", null);
    }
}
