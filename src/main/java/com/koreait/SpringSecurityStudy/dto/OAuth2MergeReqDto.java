package com.koreait.SpringSecurityStudy.dto;

import com.koreait.SpringSecurityStudy.entity.OAuth2User;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class OAuth2MergeReqDto {
    private String username;
    private String password;
    private String provider;
    private String providerUserId;

    public OAuth2User toOAuth2User(Integer userId) {
        return OAuth2User.builder()
                .userId(userId)
                .provider(this.provider)
                .providerUserId(this.providerUserId)
                .build();
    }
}
