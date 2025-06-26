package com.koreait.SpringSecurityStudy.dto;

import com.koreait.SpringSecurityStudy.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
public class ModifyEmailReqDto {
    private String email;

    // userId는 @PathVariable로 받을 것
    public User toEntity(Integer userId) {
        return User.builder()
                .userId(userId)
                .email(this.email)
                .build();
    }
}
