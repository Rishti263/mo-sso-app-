    package com.ssoapp.controller;

    import com.ssoapp.entity.User;
    import com.ssoapp.service.UserService;
    import jakarta.servlet.http.HttpSession;
    import lombok.RequiredArgsConstructor;
    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.http.HttpStatus;
    import org.springframework.http.ResponseEntity;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.stereotype.Controller;
    import org.springframework.ui.Model;
    import org.springframework.web.bind.annotation.*;

    import java.util.HashMap;
    import java.util.Map;
    import java.util.Optional;

    @Controller
    @RequestMapping("/user")
    @RequiredArgsConstructor
    public class UserController {

        private static final Logger logger = LoggerFactory.getLogger(UserController.class);
        private final UserService userService;
        private final BCryptPasswordEncoder passwordEncoder;

        // ==================== Dashboard ====================
        @GetMapping("/dashboard")
        public String userDashboard(HttpSession session, Model model) {
            User currentUser = (User) session.getAttribute("user");

            if (currentUser == null) {
                return "redirect:/login";
            }

            // Refresh user data from database
            Optional<User> refreshedUser = userService.findByUsername(currentUser.getUsername());
            if (refreshedUser.isPresent()) {
                currentUser = refreshedUser.get();
                session.setAttribute("user", currentUser);
            }

            model.addAttribute("currentUser", currentUser);
            return "user-dashboard";
        }

        // ==================== READ Operations (Self) ====================
        @GetMapping("/profile")
        @ResponseBody
        public ResponseEntity<?> getProfile(HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                // Get fresh data from database
                Optional<User> userOpt = userService.getUserById(currentUser.getId());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("status", "error", "message", "User not found"));
                }

                User user = userOpt.get();
                // Don't send password hash
                user.setPassword(null);

                return ResponseEntity.ok(user);

            } catch (Exception e) {
                logger.error("Error fetching profile: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }

        // ==================== UPDATE Operations (Self) ====================
        @PutMapping("/profile/update")
        @ResponseBody
        public ResponseEntity<?> updateProfile(@RequestBody Map<String, String> updates, HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                // Get current user from database
                Optional<User> userOpt = userService.getUserById(currentUser.getId());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("status", "error", "message", "User not found"));
                }

                User user = userOpt.get();

                // Users can only update their own email and basic info
                // They cannot change username, role, or ID
                if (updates.containsKey("email")) {
                    String newEmail = updates.get("email");

                    // Check if email is already taken by another user
                    if (userService.existsByEmail(newEmail) && !newEmail.equals(user.getEmail())) {
                        return ResponseEntity.badRequest()
                                .body(Map.of("status", "error", "message", "Email already in use"));
                    }

                    user.setEmail(newEmail);
                }

                // Allow updating additional profile fields if you have them
                // For example: firstName, lastName, phone, etc.

                User updatedUser = userService.updateUser(user.getId(), user);

                // Update session
                session.setAttribute("user", updatedUser);

                logger.info("User {} updated their profile", currentUser.getUsername());

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "Profile updated successfully",
                        "user", updatedUser
                ));

            } catch (Exception e) {
                logger.error("Error updating profile: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }

        @PostMapping("/profile/update")
        @ResponseBody
        public ResponseEntity<?> updateProfilePost(@RequestBody Map<String, String> updates, HttpSession session) {
            // Delegate to PUT method for backward compatibility
            return updateProfile(updates, session);
        }

        // ==================== Password Management ====================
        @PostMapping("/password/change")
        @ResponseBody
        public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordData, HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                String currentPassword = passwordData.get("currentPassword");
                String newPassword = passwordData.get("newPassword");
                String confirmPassword = passwordData.get("confirmPassword");

                // Validate input
                if (currentPassword == null || currentPassword.trim().isEmpty()) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "Current password is required"));
                }

                if (newPassword == null || newPassword.trim().isEmpty()) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "New password is required"));
                }

                if (!newPassword.equals(confirmPassword)) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "New passwords do not match"));
                }

                // Validate password strength (optional)
                if (newPassword.length() < 8) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error",
                                    "message", "Password must be at least 8 characters long"));
                }

                // Get user from database
                Optional<User> userOpt = userService.getUserById(currentUser.getId());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("status", "error", "message", "User not found"));
                }

                User user = userOpt.get();

                // Verify current password
                if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "Current password is incorrect"));
                }

                // Update password
                userService.resetPassword(user.getId(), newPassword);

                logger.info("User {} changed their password", currentUser.getUsername());

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "Password changed successfully"
                ));

            } catch (Exception e) {
                logger.error("Error changing password: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }

        // ==================== DELETE Operations (Self) ====================
        @DeleteMapping("/account/delete")
        @ResponseBody
        public ResponseEntity<?> deleteAccount(@RequestBody Map<String, String> confirmation, HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                // Require password confirmation for account deletion
                String password = confirmation.get("password");
                if (password == null || password.trim().isEmpty()) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error",
                                    "message", "Password confirmation required for account deletion"));
                }

                // Get user from database
                Optional<User> userOpt = userService.getUserById(currentUser.getId());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("status", "error", "message", "User not found"));
                }

                User user = userOpt.get();

                // Verify password
                if (!passwordEncoder.matches(password, user.getPassword())) {
                    return ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "Incorrect password"));
                }

                // Delete user account
                userService.deleteUser(user.getId());

                // Invalidate session
                session.invalidate();

                logger.info("User {} deleted their account", currentUser.getUsername());

                return ResponseEntity.ok(Map.of(
                        "status", "success",
                        "message", "Account deleted successfully"
                ));

            } catch (Exception e) {
                logger.error("Error deleting account: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }

        // ==================== Activity History ====================
        @GetMapping("/activity")
        @ResponseBody
        public ResponseEntity<?> getActivityHistory(HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                Map<String, Object> activity = new HashMap<>();
                activity.put("username", currentUser.getUsername());
                activity.put("role", currentUser.getRole());
                activity.put("createdAt", currentUser.getCreatedAt());
                activity.put("updatedAt", currentUser.getUpdatedAt());
                activity.put("createdBy", currentUser.getCreatedBy());

                // Add more activity data if you have login history, etc.

                return ResponseEntity.ok(activity);

            } catch (Exception e) {
                logger.error("Error fetching activity: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }

        // ==================== Profile Page ====================
        @GetMapping("/profile-page")
        public String profilePage(HttpSession session, Model model) {
            User currentUser = (User) session.getAttribute("user");

            if (currentUser == null) {
                return "redirect:/login";
            }

            // Get fresh data from database
            Optional<User> userOpt = userService.getUserById(currentUser.getId());
            if (userOpt.isPresent()) {
                currentUser = userOpt.get();
                session.setAttribute("user", currentUser);
            }

            model.addAttribute("user", currentUser);
            return "user-profile";
        }

        // ==================== Settings Page ====================
        @GetMapping("/settings")
        public String settingsPage(HttpSession session, Model model) {
            User currentUser = (User) session.getAttribute("user");

            if (currentUser == null) {
                return "redirect:/login";
            }

            model.addAttribute("user", currentUser);
            return "user-settings";
        }

        // ==================== Export User Data (GDPR Compliance) ====================
        @GetMapping("/data/export")
        @ResponseBody
        public ResponseEntity<?> exportUserData(HttpSession session) {
            try {
                User currentUser = (User) session.getAttribute("user");
                if (currentUser == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "Not authenticated"));
                }

                // Get all user data
                Optional<User> userOpt = userService.getUserById(currentUser.getId());
                if (userOpt.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("status", "error", "message", "User not found"));
                }

                User user = userOpt.get();

                // Create export data (remove sensitive info like password)
                Map<String, Object> exportData = new HashMap<>();
                exportData.put("id", user.getId());
                exportData.put("username", user.getUsername());
                exportData.put("email", user.getEmail());
                exportData.put("role", user.getRole());
                exportData.put("createdBy", user.getCreatedBy());
                exportData.put("createdAt", user.getCreatedAt());
                exportData.put("updatedAt", user.getUpdatedAt());

                logger.info("User {} exported their data", currentUser.getUsername());

                return ResponseEntity.ok(exportData);

            } catch (Exception e) {
                logger.error("Error exporting user data: ", e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", e.getMessage()));
            }
        }
    }