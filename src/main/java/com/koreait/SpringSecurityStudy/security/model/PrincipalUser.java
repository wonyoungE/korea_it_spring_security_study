package com.koreait.SpringSecurityStudy.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.koreait.SpringSecurityStudy.entity.UserRole;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
// User가 UserDetails(interface)를 구현함 => User가 UserDetails 자체
public class PrincipalUser implements UserDetails {
    private Integer userId;
    private String username;
    @JsonIgnore // 비밀번호 제외하고 return
    private String password;
    private String email;
    private List<UserRole> userRoles;

    // 권한 목록을 가져오는 메서드
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // map -> list 안에 들어있는 요소 하나하나에 적용시키는 것
        // filter -> 조건으로 걸러내는 것
        return userRoles.stream().map(userRole -> new SimpleGrantedAuthority(userRole.getRole().getRoleName()))
                .collect(Collectors.toList());
    }
}