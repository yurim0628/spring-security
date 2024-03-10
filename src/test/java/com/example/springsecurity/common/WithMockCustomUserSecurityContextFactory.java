package com.example.springsecurity.common;

import com.example.springsecurity.security.PrincipalDetails;
import com.example.springsecurity.user.model.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

public class WithMockCustomUserSecurityContextFactory implements WithSecurityContextFactory<WithMockCustomUser> {

    @Override
    public SecurityContext createSecurityContext(WithMockCustomUser annotation) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        User user = User.builder()
                .email(annotation.username())
                .password(annotation.password())
                .build();
        PrincipalDetails userDetails = new PrincipalDetails(user);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                "",
                userDetails.getAuthorities()
        );
        context.setAuthentication(usernamePasswordAuthenticationToken);
        return context;
    }
}
