package com.koreait.SpringSecurityStudy.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserRole { // User와 Role 매핑 테이블
    private Integer userRoleId;
    private Integer userId;
    private Integer roleId;
    private LocalDateTime createDt;
    private LocalDateTime updateDt;

    private Role role;
}
