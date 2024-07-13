package com.lfhardware.gateway.api;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/gateway")
@Slf4j
public class UserApi {

    @GetMapping("/user-info")
    public Mono<String> findUsername(@AuthenticationPrincipal AuthenticationPrincipal authenticationPrincipal){

        return ReactiveSecurityContextHolder.getContext().flatMap(context-> {
            log.info("Finding user information : {}", context.getAuthentication().getName());
            return Mono.just(context.getAuthentication().getName());
        });
    }
}
