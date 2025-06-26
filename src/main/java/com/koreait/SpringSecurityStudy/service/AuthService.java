package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.*;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.entity.UserRole;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.repository.UserRoleRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    // 회원가입
    public ApiRespDto<?> addUser(SignupReqDto signupReqDto) {
        // 비밀번호 암호화 위해서 bCryptPasswordEncoder 넣어줌
        Optional<User> optionalUser = userRepository.addUser(signupReqDto.toEntity(bCryptPasswordEncoder));
        // 생성된 계정에 해당하는 권한 목록 추가
        UserRole userRole = UserRole.builder()
                .userId(optionalUser.get().getUserId())
                .roleId(3)  // 임시 사용자 role
                .build();
        userRoleRepository.addUserRole(userRole);
        return new ApiRespDto<>("success", "회원가입 성공", optionalUser);
    }

    public ApiRespDto<?> signin(SigninReqDto signinReqDto) {
        Optional<User> optionalUser = userRepository.getUserByUsername(signinReqDto.getUsername());
        if(optionalUser.isEmpty()) {
            // 뭐가 맞고 틀렸다고 알려주면 안됨 -> 보안상의 문제
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        User user = optionalUser.get();
        System.out.println(user.toString());
        // 사용자가 입력한 비밀번호와 DB에 저장된 비밀번호가 같은지 확인
        if(!bCryptPasswordEncoder.matches(signinReqDto.getPassword(), user.getPassword())) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        System.out.println("로그인 성공!");
        // 로그인 성공시 토큰 생성
        String token = jwtUtil.generateAccessToken(user.getUserId().toString());
        return new ApiRespDto<>("success", "로그인 성공", token);
    }

    public ApiRespDto<?> modifyEmail(Integer userId, ModifyEmailReqDto modifyEmailReqDto) {
        User user = modifyEmailReqDto.toEntity(userId);
        int result = userRepository.updateEmail(user);
        return new ApiRespDto<>("success", "이메일 수정 성공", result);
    }

    public ApiRespDto<?> modifyPassword(ModifyPasswordReqDto modifyPasswordReqDto, PrincipalUser principalUser) {
        // PrincipalUser는 왜 들고옴? ContextHolder에 등록된 user 정보의 password와 사용자로부터 입력받은 현재 비밀번호랑 같은지 비교 위함
        if(!bCryptPasswordEncoder.matches(modifyPasswordReqDto.getOldPassword(), principalUser.getPassword())) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }
        if(!modifyPasswordReqDto.getNewPassword().equals(modifyPasswordReqDto.getNewPasswordCheck())) {
            return new ApiRespDto<>("failed", "새 비밀번호가 일치하지 않습니다.", null);
        }

        String password = bCryptPasswordEncoder.encode(modifyPasswordReqDto.getNewPassword());
        int result = userRepository.updatePassword(principalUser.getUserId(), password);

        return new ApiRespDto<>("success", "비밀번호 수정 성공", result);
    }
}
