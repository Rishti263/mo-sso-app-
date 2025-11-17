package com.ssoapp.controller;

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

@Controller
@RequestMapping("/superadmin")
@RequiredArgsConstructor
public class SuperAdminController {

    private static final Logger logger = LoggerFactory.getLogger(SuperAdminController.class);
    private final UserService userService;

    // ==================== Dashboard ====================
    @GetMapping("/dashboard")
    public String superAdminDashboard(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
            return "redirect:/login";
        }

        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("adminCount", userService.countByRole("ADMIN"));
        model.addAttribute("userCount", userService.countByRole("ENDUSER"));
        model.addAttribute("superAdminCount", userService.countByRole("SUPERADMIN"));

        return "superadmin-dashboard";
    }

    // ==================== CREATE Operations ====================
    @PostMapping("/user/create")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody User user, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
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

            // Super admin can create any type of user (SUPERADMIN, ADMIN, ENDUSER)
            user.setCreatedBy(currentUser.getUsername());
            User createdUser = userService.registerUser(user);

            logger.info("Super Admin {} created new user: {} with role: {}",
                    currentUser.getUsername(), user.getUsername(), user.getRole());

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "User created successfully",
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
    public ResponseEntity<?> getAllUsers(HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            List<User> users = userService.getAllUsers();
            return ResponseEntity.ok(users);

        } catch (Exception e) {
            logger.error("Error fetching users: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/user/{id}")
    @ResponseBody
    public ResponseEntity<?> getUserById(@PathVariable Long id, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Optional<User> user = userService.getUserById(id);
            if (user.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("status", "error", "message", "User not found"));
            }

            return ResponseEntity.ok(user.get());

        } catch (Exception e) {
            logger.error("Error fetching user: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    @GetMapping("/users/role/{role}")
    @ResponseBody
    public ResponseEntity<?> getUsersByRole(@PathVariable String role, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            List<User> users = userService.getUsersByRole(role.toUpperCase());
            return ResponseEntity.ok(users);

        } catch (Exception e) {
            logger.error("Error fetching users by role: ", e);
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
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
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

            // Prevent super admin from demoting themselves
            if (existingUser.getUsername().equals(currentUser.getUsername()) &&
                    !"SUPERADMIN".equals(userUpdate.getRole())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error",
                                "message", "Cannot change your own role from SUPERADMIN"));
            }

            // Update user
            User updatedUser = userService.updateUser(id, userUpdate);

            logger.info("Super Admin {} updated user: {} (ID: {})",
                    currentUser.getUsername(), updatedUser.getUsername(), id);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "User updated successfully",
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
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
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

            // Prevent super admin from deleting themselves
            if (userToDelete.getUsername().equals(currentUser.getUsername())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error", "message", "Cannot delete your own account"));
            }

            // Prevent deleting the last super admin
            if ("SUPERADMIN".equals(userToDelete.getRole()) &&
                    userService.countByRole("SUPERADMIN") <= 1) {
                return ResponseEntity.badRequest()
                        .body(Map.of("status", "error",
                                "message", "Cannot delete the last super admin"));
            }

            userService.deleteUser(id);

            logger.info("Super Admin {} deleted user: {} (ID: {})",
                    currentUser.getUsername(), userToDelete.getUsername(), id);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "User deleted successfully"
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

    // ==================== Statistics ====================
    @GetMapping("/stats")
    @ResponseBody
    public ResponseEntity<?> getStatistics(HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            Map<String, Object> stats = new HashMap<>();
            stats.put("totalUsers", userService.getAllUsers().size());
            stats.put("superAdmins", userService.countByRole("SUPERADMIN"));
            stats.put("admins", userService.countByRole("ADMIN"));
            stats.put("endUsers", userService.countByRole("ENDUSER"));

            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            logger.error("Error fetching statistics: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // ==================== SSO Configuration ====================
    @GetMapping("/sso-config")
    public String ssoConfig(HttpSession session, Model model) {
        User currentUser = (User) session.getAttribute("user");

        if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
            return "redirect:/login";
        }

        return "sso-config";
    }

    // ==================== Search Operations ====================
    @GetMapping("/user/search")
    @ResponseBody
    public ResponseEntity<?> searchUsers(@RequestParam String query, HttpSession session) {
        try {
            User currentUser = (User) session.getAttribute("user");
            if (currentUser == null || !"SUPERADMIN".equals(currentUser.getRole())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Unauthorized"));
            }

            List<User> users = userService.searchUsers(query);
            return ResponseEntity.ok(users);

        } catch (Exception e) {
            logger.error("Error searching users: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", e.getMessage()));
        }
    }
}