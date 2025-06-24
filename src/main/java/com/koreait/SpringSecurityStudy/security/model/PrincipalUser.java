package com.koreait.SpringSecurityStudy.security.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
// User가 UserDetails(interface)를 구현함 => User가 UserDetails 자체
public class PrincipalUser implements UserDetails {
    private Integer userId;
    private String username;
    private String password;
    private String email;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }
}
