package com.ssoapp.config;

import com.ssoapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ApplicationStartupRunner implements CommandLineRunner {

    private final UserService userService;

    @Override
    public void run(String... args) throws Exception {
        // Create initial super admin if not exists
        userService.createInitialSuperAdmin();
    }
}