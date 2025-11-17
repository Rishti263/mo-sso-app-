package com.ssoapp.controller;

import com.ssoapp.entity.User;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;

    @GetMapping("/")
    public String index(HttpSession session) {
        User user = (User) session.getAttribute("user");
        if (user != null) {
            return getRedirectByRole(user.getRole());
        }
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(HttpSession session) {
        User user = (User) session.getAttribute("user");
        if (user != null) {
            return getRedirectByRole(user.getRole());
        }
        return "login";
    }

    @PostMapping("/api/auth/login")
    public void apiLogin(@RequestParam String username,
                         @RequestParam String password,
                         HttpServletRequest request,
                         HttpServletResponse response) throws Exception {

        try {
            Optional<User> userOpt = userService.findByUsername(username);
            if (!userOpt.isPresent()) {
                response.sendRedirect("/login?error=user_not_found");
                return;
            }

            User user = userOpt.get();

            // Validate password
            if (!userService.validatePassword(password, user.getPassword())) {
                response.sendRedirect("/login?error=invalid_credentials");
                return;
            }

            // Create new session
            HttpSession session = request.getSession(true);

            // Prepare Spring Security role
            String role = user.getRole() != null ? user.getRole().trim().toUpperCase() : "ENDUSER";
            String springRole = role.startsWith("ROLE_") ? role : "ROLE_" + role;

            // Create authentication token
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            null,
                            Collections.singletonList(new SimpleGrantedAuthority(springRole))
                    );

            // Set security context
            SecurityContext ctx = SecurityContextHolder.createEmptyContext();
            ctx.setAuthentication(authentication);
            SecurityContextHolder.setContext(ctx);

            // Save security context to session
            new HttpSessionSecurityContextRepository().saveContext(ctx, request, response);

            // Store user in session
            session.setAttribute("user", user);

            // Redirect based on role
            response.sendRedirect(getRedirectPath(user.getRole()));

        } catch (Exception e) {
            e.printStackTrace();
            response.sendRedirect("/login?error=auth_failed");
        }
    }

    @GetMapping("/register")
    public String registerPage(HttpSession session) {
        User user = (User) session.getAttribute("user");
        if (user != null) return "redirect:/";
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam String email,
                           @RequestParam String role,
                           Model model) {

        try {
            if (userService.existsByUsername(username)) {
                model.addAttribute("error", "Username already exists.");
                return "register";
            }
            if (userService.existsByEmail(email)) {
                model.addAttribute("error", "Email already registered.");
                return "register";
            }

            User user = new User();
            user.setUsername(username);
            user.setPassword(password); // UserService will encode
            user.setEmail(email);
            user.setRole(role);         // SUPERADMIN, ADMIN or ENDUSER

            userService.registerUser(user);
            model.addAttribute("success", "Registration successful. Please login.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        SecurityContextHolder.clearContext();
        return "redirect:/login?logout=true";
    }

    private String getRedirectByRole(String role) {
        if (role == null) return "redirect:/login";

        switch (role.toUpperCase()) {
            case "SUPERADMIN":
                return "redirect:/superadmin/dashboard";
            case "ADMIN":
                return "redirect:/admin/dashboard";
            case "ENDUSER":
                return "redirect:/user/dashboard";
            default:
                return "redirect:/login";
        }
    }

    private String getRedirectPath(String role) {
        if (role == null) return "/login";

        switch (role.toUpperCase()) {
            case "SUPERADMIN":
                return "/superadmin/dashboard";
            case "ADMIN":
                return "/admin/dashboard";
            case "ENDUSER":
                return "/user/dashboard";
            default:
                return "/login";
        }
    }
}