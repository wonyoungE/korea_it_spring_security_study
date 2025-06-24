package com.koreait.SpringSecurityStudy.security.filter;

import com.koreait.SpringSecurityStudy.entity.User;
import com.koreait.SpringSecurityStudy.repository.UserRepository;
import com.koreait.SpringSecurityStudy.security.jwt.JwtUtil;
import com.koreait.SpringSecurityStudy.security.model.PrincipalUser;
import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

// filter 직접 커스텀해서 사용할 것
@Component  // Autowired로 쓸 거기 때문에 bean 등록해둬야 함.
public class JwtAuthenticationFilter implements Filter {
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Override
    // 이 메서드에서 AuthenticationManager, AuthenticationProvider, UserDetailsService, UserDetails 전부 구현
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;   // 요청에 JWT 토큰 들어있음?
        // 요청 방식 리스트
        // list에 있는 요청 방식이 아니면 이 필터는 아무것도 하지 않고 다음 필터나 컨트롤러에게 넘김
        // 다음 필터가 뭐지? ㅜㅜ 내일 gpt한테 물어보기
        List<String> methods = List.of("POST", "PUT", "GET", "DELETE", "PATCH");
        if(!methods.contains(request.getMethod())) {
            // doFilter()가 하는 일 -> 다음 필터에게 요청을 넘김, 최종적으로 서블릿(컨트롤러)까지 요청 전달
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }
        String authorization = request.getHeader("Authorization");
        System.out.println("Bearer 토큰: " + authorization);
        if(jwtUtil.isBearer(authorization)) {
            String accessToken = jwtUtil.removeBearer(authorization);
            try {
                Claims claims = jwtUtil.getClaims(accessToken);
                // getClaims()에서 -> jwtParser.parseClaimsJws(token).getBody()
                // 토큰에서 Claims(payload, 사용자 정보 담김)를 추출하고
                // 이 때 서명 검증도 같이 진행 -> 서명 위조나 만료 시 예외 발생
                String id = claims.getId();
                // UserDetailsService 시작
                Integer userId = Integer.parseInt(id);
                // AuthenticationManager 없이 직접 사용자 찾아서 인증 처리
                Optional<User> optionalUser = userRepository.getUserByUserId(userId);
                // optionalUser가 있으면 -> 인증, null이면 -> 인증 실패
                optionalUser.ifPresentOrElse((user) -> {
                    // DB에서 조회된 User 객체를 Spring Security 인증 객체(PrincipalUser)로 변환
                    // UserDetailsService 직접 구현한 것과 같음
                    PrincipalUser principalUser = PrincipalUser.builder()
                            .userId(user.getUserId())
                            .username(user.getUsername())
                            .password(user.getPassword())
                            .email(user.getEmail())
                            .build();
                    // UsernamePasswordAuthenticationToken 직접 생성
                    // 두 번째 매개변수는 패스워드인데, 우리는 이미 인증이 완료된 상태라서 비워둠
                    // 로그인을 토큰을 발급받음, 클라이언트는 이 필터를 계속 타면서 토큰 파싱을 계속할 것임 -> user가 db에 있으면 set해두는 것
                    // getClaims하면서 확인을 한 것
                    // 토큰이 있다는 것 자체가 인증이 완료되었다는 것
                    Authentication authentication = new UsernamePasswordAuthenticationToken(principalUser, "", principalUser.getAuthorities());
                    // spring security의 인증 컨텍스트에 인증 객체 저장 -> 이후 요청은 인증된 사용자로 간주됨
                    // 이제 context에 사용자 정보를 저장함(set) -> 다음 필터 타고갈 때는 인증된 사용자로 간주되어 다 지나가고, Controller로 가게됨
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    System.out.println("인증 완료");
                    System.out.println(authentication.getName());
                }, () -> {
                    throw new AuthenticationServiceException("인증 실패");
                });
            } catch (RuntimeException e) {
                e.printStackTrace();
            }
        }
        // 인증 실패든 성공이든 필터링을 중단하지 않고 다음 필터로 넘어감
        // doFilter() 기점으로 전처리 후처리
        filterChain.doFilter(servletRequest, servletResponse);
        System.out.println("후처리");
    }
}
