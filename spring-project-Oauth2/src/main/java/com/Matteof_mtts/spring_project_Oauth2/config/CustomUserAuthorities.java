package com.Matteof_mtts.spring_project_Oauth2.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Data
@AllArgsConstructor
public class CustomUserAuthorities {

    private String username;
    private List< ? extends GrantedAuthority> authorities;

}
