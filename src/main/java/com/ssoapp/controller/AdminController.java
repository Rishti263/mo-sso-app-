package com.ssoapp.controller;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import com.ssoapp.entity.User;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);
    private final UserService userService;

    // ==================== Dashboard ====================
    @GetMapping("/dashboard")
    public String adminDashboard(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
            return "redirect:/login";
        }

        // Admin can only see and manage end users
        List<User> users = userService.getAllUsers().stream()
                .filter(u -> "ENDUSER".equals(u.getRole()))
                .collect(Collectors.toList());

        model.addAttribute("users", users);
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("userCount", users.size());

        return "admin-dashboard";
    }

    // ==================== CREATE Operations ====================
    @PostMapping("/user/create")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody User user, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            // Validate input
            if (user.getUsername() == null || user.getUsername().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Username is required"));
            }

            if (user.getEmail() == null || user.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Email is required"));
            }

            // Check if username already exists
            if (userService.existsByUsername(user.getUsername())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Username already exists"));
            }

            // Check if email already exists
            if (userService.existsByEmail(user.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Email already exists"));
            }

            // Admin can only create ENDUSER
            user.setRole("ENDUSER");
            user.setCreatedBy(currentUser.getUsername());
            User createdUser = userService.registerUser(user);

            logger.info("Admin {} created new end user: {}",
                    currentUser.getUsername(), user.getUsername());

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "End user created successfully",
                    "userId", createdUser.getId()
            ));

        } catch (Exception e) {
            logger.error("Error creating user: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== READ Operations ====================
    @GetMapping("/users")
    @ResponseBody
    public ResponseEntity<?> getAllEndUsers(HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            // Admin can only see end users
            List<User> endUsers = userService.getAllUsers().stream()
                    .filter(u -> "ENDUSER".equals(u.getRole()))
                    .collect(Collectors.toList());

            return ResponseEntity.ok(endUsers);

        } catch (Exception e) {
            logger.error("Error fetching end users: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/user/{id}")
    @ResponseBody
    public ResponseEntity<?> getUserById(@PathVariable Long id, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Optional<User> userOpt = userService.getUserById(id);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "error", "message", "User not found"));
            }

            User user = userOpt.get();

            // Admin can only view end users
            if (!"ENDUSER".equals(user.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error",
                                "message", "You can only view end users"));
            }

            return ResponseEntity.ok(user);

        } catch (Exception e) {
            logger.error("Error fetching user: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== UPDATE Operations ====================
    @PutMapping("/user/update/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User userUpdate, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            // Check if user exists
            Optional<User> existingUserOpt = userService.getUserById(id);
            if (existingUserOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "error", "message", "User not found"));
            }

            User existingUser = existingUserOpt.get();

            // Admin can only update ENDUSER
            if (!"ENDUSER".equals(existingUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error",
                                "message", "You can only update end users"));
            }

            // Force role to remain ENDUSER
            userUpdate.setRole("ENDUSER");

            User updatedUser = userService.updateUser(id, userUpdate);

            logger.info("Admin {} updated end user: {} (ID: {})",
                    currentUser.getUsername(), updatedUser.getUsername(), id);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "End user updated successfully",
                    "user", updatedUser
            ));

        } catch (Exception e) {
            logger.error("Error updating user: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/user/update/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUserPost(@PathVariable Long id, @RequestBody User userUpdate, HttpSession session) {
        // Delegate to PUT method for backward compatibility
        return updateUser(id, userUpdate, session);
    }

    // ==================== DELETE Operations ====================
    @DeleteMapping("/user/delete/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUser(@PathVariable Long id, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            // Check if user exists
            Optional<User> userToDeleteOpt = userService.getUserById(id);
            if (userToDeleteOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "error", "message", "User not found"));
            }

            User userToDelete = userToDeleteOpt.get();

            // Admin can only delete ENDUSER
            if (!"ENDUSER".equals(userToDelete.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error",
                                "message", "You can only delete end users"));
            }

            userService.deleteUser(id);

            logger.info("Admin {} deleted end user: {} (ID: {})",
                    currentUser.getUsername(), userToDelete.getUsername(), id);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "End user deleted successfully"
            ));

        } catch (Exception e) {
            logger.error("Error deleting user: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @PostMapping("/user/delete/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUserPost(@PathVariable Long id, HttpSession session) {
        // Delegate to DELETE method for backward compatibility
        return deleteUser(id, session);
    }

    // ==================== Bulk Operations ====================
    @PostMapping("/users/create-bulk")
    @ResponseBody
    public ResponseEntity<?> createBulkUsers(@RequestBody List<User> users, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Map<String, Object> result = new HashMap<>();
            List<String> created = new ArrayList<>();
            List<String> failed = new ArrayList<>();

            for (User user : users) {
                try {
                    // Force all to be ENDUSER
                    user.setRole("ENDUSER");
                    user.setCreatedBy(currentUser.getUsername());

                    if (!userService.existsByUsername(user.getUsername()) &&
                            !userService.existsByEmail(user.getEmail())) {
                        userService.registerUser(user);
                        created.add(user.getUsername());
                    } else {
                        failed.add(user.getUsername() + " (already exists)");
                    }
                } catch (Exception e) {
                    failed.add(user.getUsername() + " (" + e.getMessage() + ")");
                }
            }

            result.put("created", created);
            result.put("failed", failed);
            result.put("status", "completed");

            logger.info("Admin {} bulk created {} users, {} failed",
                    currentUser.getUsername(), created.size(), failed.size());

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            logger.error("Error in bulk user creation: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== Statistics ====================
    @GetMapping("/stats")
    @ResponseBody
    public ResponseEntity<?> getStatistics(HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Map<String, Object> stats = new HashMap<>();
            stats.put("totalEndUsers", userService.countByRole("ENDUSER"));
            stats.put("createdByMe", userService.getUsersCreatedBy(currentUser.getUsername()).size());
            stats.put("recentUsers", userService.getRecentUsers(7)); // Last 7 days

            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            logger.error("Error fetching statistics: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== Search Operations ====================
    @GetMapping("/user/search")
    @ResponseBody
    public ResponseEntity<?> searchEndUsers(@RequestParam String query, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            // Search only among end users
            List<User> users = userService.searchUsers(query).stream()
                    .filter(u -> "ENDUSER".equals(u.getRole()))
                    .collect(Collectors.toList());

            return ResponseEntity.ok(users);

        } catch (Exception e) {
            logger.error("Error searching users: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== SSO Configuration ====================
    @GetMapping("/sso-config")
    public String ssoConfig(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
            return "redirect:/login";
        }

        return "sso-config";
    }

    // ==================== Password Reset ====================
    @PostMapping("/user/{id}/reset-password")
    @ResponseBody
    public ResponseEntity<?> resetUserPassword(@PathVariable Long id,
                                               @RequestBody Map<String, String> request,
                                               HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || (!"ADMIN".equals(currentUser.getRole()) && !"SUPERADMIN".equals(currentUser.getRole()))) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Optional<User> userOpt = userService.getUserById(id);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "error", "message", "User not found"));
            }

            User user = userOpt.get();

            // Admin can only reset password for end users
            if (!"ENDUSER".equals(user.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error",
                                "message", "You can only reset passwords for end users"));
            }

            String newPassword = request.get("newPassword");
            if (newPassword == null || newPassword.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "New password is required"));
            }

            userService.resetPassword(id, newPassword);

            logger.info("Admin {} reset password for user: {} (ID: {})",
                    currentUser.getUsername(), user.getUsername(), id);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Password reset successfully"
            ));

        } catch (Exception e) {
            logger.error("Error resetting password: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }
}