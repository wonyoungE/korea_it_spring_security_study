package com.koreait.SpringSecurityStudy.service;

import com.koreait.SpringSecurityStudy.dto.ApiRespDto;
import com.koreait.SpringSecurityStudy.dto.SendMailReqDto;
import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MailService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JavaMailSender javaMailSender;

    // 이메일 인증, 임시 사용자 -> 일반 사용자
    public ApiRespDto<?> sendMail(SendMailReqDto sendMailReqDto, PrincipalUser principalUser) {
        // 사용자가 입력한 이메일과 로그인한 사용자(토큰)의 이메일이 일치하는 지 먼저 확인
        if(!principalUser.getEmail().equals(sendMailReqDto.getEmail())) {
            return new ApiRespDto<>("failed", "잘못된 접근입니다.", null);
        }

        // 해당 이메일이 회원 정보에 있는지 확인해야 함 ?? 토큰 등록되면 있는 거 아님.. ? .. ㅜ
        Optional<User> optionalUser = userRepository.getUserByEmail(sendMailReqDto.getEmail());
        if(optionalUser.isEmpty()) {
            return new ApiRespDto<>("failed", "사용자 정보를 확인해주세요.", null);
        }

        User user = optionalUser.get();
        // 유저의 권한들 중 3번(임시 사용자)인 게 있는지 확인
        boolean hasTempRole = user.getUserRoles().stream().anyMatch(userRole -> userRole.getRoleId() == 3);
        if(!hasTempRole) {
            return new ApiRespDto<>("failed", "인증이 필요한 계정이 아닙니다.", null);
        }

        // 메일 인증 토큰 생성
        String token = jwtUtil.generateMailVerifyToken(user.getUserId().toString());

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("이메일 인증 메일입니다.");    // 메일 제목
        message.setText("링크를 클릭해 인증을 완료해주세요: " +
                "http://localhost:8080/mail/verify?verifyToken=" + token);
        javaMailSender.send(message);

        return new ApiRespDto<>("success", "인증 메일이 전송되었습니다. 메일함을 확인해주세요.", null);
    }
}
