package com.ssoapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for SSO endpoints
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(
                                "/api/**",
                                "/sso/**",
                                "/saml2/**",
                                "/oauth2/**"
                        )
                )

                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(
                                "/",
                                "/login",
                                "/register",
                                "/error",
                                "/favicon.ico",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/webjars/**"
                        ).permitAll()

                        // SSO endpoints - MUST be permitAll
                        .requestMatchers(
                                "/api/jwt/**",
                                "/api/auth/**",
                                "/sso/**",
                                "/sso/oauth/**",
                                "/sso/oauth/login",
                                "/sso/oauth/callback",
                                "/sso/oauth/config",
                                "/sso/saml/**",
                                "/sso/saml/login",
                                "/sso/saml/acs",
                                "/sso/saml/metadata",
                                "/sso/saml/sp-info",
                                "/sso/saml/config"
                        ).permitAll()

                        // Role-based access
                        .requestMatchers("/superadmin/**").hasRole("SUPERADMIN")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUPERADMIN")
                        .requestMatchers("/user/**").hasAnyRole("ENDUSER", "ADMIN", "SUPERADMIN")

                        // All other requests require authentication
                        .anyRequest().authenticated()
                )

                // Form login configuration
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(roleSuccessHandler())
                        .failureUrl("/login?error")
                        .permitAll()
                )

                // Logout configuration
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                // Security context persistence
                .securityContext(sc -> sc
                        .requireExplicitSave(false)
                        .securityContextRepository(new HttpSessionSecurityContextRepository())
                )

                // Session management
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(
                                org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED
                        )
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )

                // Disable request cache to prevent redirect loops
                .requestCache(rc -> rc.disable())

                // Exception handling - FIX: using || instead of |
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) -> {
                            String uri = req.getRequestURI();
                            // Fixed: Using proper OR operator
                            if (uri.startsWith("/api/auth/")
                                    || uri.startsWith("/api/jwt/")
                                    || uri.startsWith("/sso/")
                                    || uri.startsWith("/saml2/")
                                    || uri.startsWith("/oauth2/")
                                    || uri.startsWith("/sso/oauth/")
                                    || uri.startsWith("/sso/saml/")
                                    || uri.startsWith("/api/oauth/")) {
                                // Return 401 for API/SSO endpoints
                                res.setStatus(401);
                                res.getWriter().write("Unauthorized - SSO endpoint");
                            } else {
                                // Redirect to login for regular pages
                                res.sendRedirect("/login");
                            }
                        })
                        .accessDeniedHandler((req, res, e) -> res.sendRedirect("/login?denied"))
                );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler roleSuccessHandler() {
        return (request, response, authentication) -> {
            String role = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(a -> a.startsWith("ROLE_"))
                    .findFirst()
                    .orElse("ROLE_ENDUSER");

            String redirectUrl = switch (role) {
                case "ROLE_SUPERADMIN" -> "/superadmin/dashboard";
                case "ROLE_ADMIN" -> "/admin/dashboard";
                default -> "/user/dashboard";
            };

            response.sendRedirect(redirectUrl);
        };
    }
}
























//package com.ssoapp.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                // Exempt SSO and API callbacks from CSRF to prevent 403 on POST/redirects
//                .csrf(csrf -> csrf.ignoringRequestMatchers(
//                        "/api/**",
//                        "/sso/**",
//                        "/saml2/**",
//                        "/oauth2/**"
//                ))
//                .authorizeHttpRequests(auth -> auth
//                        // Public
//                        .requestMatchers(
//                                "/",
//                                "/login",
//                                "/register",
//                                "/error",
//                                "/favicon.ico",
//                                "/css/**",
//                                "/js/**",
//                                "/images/**",
//                                "/webjars/**"
//                        ).permitAll()
//
//                        // SSO entrypoints and callbacks must remain open
//                        .requestMatchers(
//                                "/api/jwt/**",          // <- add this
//                                "/api/auth/**",
//                                "/sso/**",
//                                "/saml2/**",
//                                "/oauth2/**",
//                                "/api/oauth/**",    // OAuth callback
//                                "/sso/oauth/**",    // OAuth start
//                                "/sso/saml/**"      // SAML start + ACS
//                        ).permitAll()
//
//                        // Role-gated
//                        .requestMatchers("/superadmin/**").hasRole("SUPERADMIN")
//                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUPERADMIN")
//                        .requestMatchers("/user/**").hasAnyRole("ENDUSER", "ADMIN", "SUPERADMIN")
//
//                        // Everything else requires auth
//                        .anyRequest().authenticated()
//                )
//                // Form login (independent from SSO)
//                .formLogin(form -> form
//                        .loginPage("/login")
//                        .loginProcessingUrl("/perform_login")
//                        .successHandler(roleSuccessHandler())
//                        .failureUrl("/login?error")
//                        .permitAll()
//                )
//                // Logout
//                .logout(logout -> logout
//                        .logoutUrl("/logout")
//                        .logoutSuccessUrl("/login?logout")
//                        .invalidateHttpSession(true)
//                        .deleteCookies("JSESSIONID")
//                        .permitAll()
//                )
//                // Persist security context in session; we also save it manually in SSO controller
//                .securityContext(sc -> sc
//                        .requireExplicitSave(false)
//                        .securityContextRepository(new HttpSessionSecurityContextRepository())
//                )
//                .sessionManagement(sm -> sm
//                        .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)
//                        .maximumSessions(1)
//                        .maxSessionsPreventsLogin(false)
//                )
//                // Avoid redirecting back to savedRequest that may be unauth’ed
//                .requestCache(rc -> rc.disable())
//                // Avoid redirect loops on SSO endpoints
//                .exceptionHandling(ex -> ex
//                        .authenticationEntryPoint((req, res, e) -> {
//                            String uri = req.getRequestURI();
//                            if (uri.startsWith("/api/auth/")
//                                    || uri.startsWith("/sso/")
//                                    || uri.startsWith("/saml2/")
//                                    || uri.startsWith("/oauth2/")
//                                    || uri.startsWith("/sso/oauth/")
//                                    | uri.startsWith("/sso/saml/")
//                                    | uri.startsWith("/api/oauth/")
//                            ) {
//                                res.sendError(401, "Unauthorized");
//                            } else {
//                                res.sendRedirect("/login");
//                            }
//                        })
//                        .accessDeniedHandler((req, res, e) -> res.sendRedirect("/login?denied"))
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    public AuthenticationSuccessHandler roleSuccessHandler() {
//        return (request, response, authentication) -> {
//            String role = authentication.getAuthorities().stream()
//                    .map(GrantedAuthority::getAuthority)
//                    .filter(a -> a.startsWith("ROLE_"))
//                    .findFirst()
//                    .orElse("ROLE_ENDUSER");
//
//            String redirectUrl = switch (role) {
//                case "ROLE_SUPERADMIN" -> "/superadmin/dashboard";
//                case "ROLE_ADMIN"      -> "/admin/dashboard";
//                default                -> "/user/dashboard";
//            };
//
//            response.sendRedirect(redirectUrl);
//        };
//    }
//}
