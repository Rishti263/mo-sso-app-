package com.ssoapp.service;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;   // used in createBulkUsers


import com.ssoapp.entity.User;
import com.ssoapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    // ==================== CREATE Operations ====================
    public User registerUser(User user) {
        // Encode password if it's not already encoded
        if (user.getPassword() != null && !user.getPassword().isEmpty() && !user.getPassword().startsWith("$2a$")) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }

        // Set creation timestamp if not set
        if (user.getCreatedAt() == null) {
            user.setCreatedAt(LocalDateTime.now());
        }
        user.setUpdatedAt(LocalDateTime.now());

        User savedUser = userRepository.save(user);
        logger.info("User registered: {} with role: {}", savedUser.getUsername(), savedUser.getRole());
        return savedUser;
    }

    // ==================== READ Operations ====================
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public List<User> getUsersByRole(String role) {
        return userRepository.findByRole(role);
    }

    public long countByRole(String role) {
        return userRepository.countByRole(role);
    }

    public List<User> getUsersCreatedBy(String createdBy) {
        return userRepository.findByCreatedBy(createdBy);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    // ==================== UPDATE Operations ====================
    public User updateUser(Long id, User userDetails) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));

        // Update fields
        if (userDetails.getUsername() != null && !userDetails.getUsername().isEmpty()) {
            user.setUsername(userDetails.getUsername());
        }

        if (userDetails.getEmail() != null && !userDetails.getEmail().isEmpty()) {
            user.setEmail(userDetails.getEmail());
        }

        if (userDetails.getRole() != null && !userDetails.getRole().isEmpty()) {
            user.setRole(userDetails.getRole());
        }

        // Update password only if provided and not empty
        if (userDetails.getPassword() != null && !userDetails.getPassword().isEmpty()) {
            // Check if password needs encoding
            if (!userDetails.getPassword().startsWith("$2a$")) {
                user.setPassword(passwordEncoder.encode(userDetails.getPassword()));
            } else {
                user.setPassword(userDetails.getPassword());
            }
        }

        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        logger.info("User updated: {} (ID: {})", updatedUser.getUsername(), id);
        return updatedUser;
    }

    public void resetPassword(Long userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(LocalDateTime.now());

        userRepository.save(user);
        logger.info("Password reset for user: {} (ID: {})", user.getUsername(), userId);
    }

    // ==================== DELETE Operations ====================
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("User not found with id: " + id);
        }

        userRepository.deleteById(id);
        logger.info("User deleted with ID: {}", id);
    }

    public void deleteUsersByRole(String role) {
        List<User> users = userRepository.findByRole(role);
        userRepository.deleteAll(users);
        logger.info("Deleted {} users with role: {}", users.size(), role);
    }

    // ==================== SEARCH Operations ====================
    public List<User> searchUsers(String query) {
        if (query == null || query.trim().isEmpty()) {
            return getAllUsers();
        }

        String searchTerm = query.toLowerCase().trim();

        return userRepository.findAll().stream()
                .filter(user ->
                        user.getUsername().toLowerCase().contains(searchTerm) ||
                                user.getEmail().toLowerCase().contains(searchTerm) ||
                                (user.getRole() != null && user.getRole().toLowerCase().contains(searchTerm))
                )
                .collect(Collectors.toList());
    }

    public List<User> searchUsersByUsernameOrEmail(String username, String email) {
        return userRepository.findByUsernameContainingOrEmailContaining(username, email);
    }

    // ==================== VALIDATION Operations ====================
    public boolean validatePassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    // ==================== STATISTICS Operations ====================
    public long getTotalUserCount() {
        return userRepository.count();
    }

    public List<User> getRecentUsers(int days) {
        LocalDateTime since = LocalDateTime.now().minusDays(days);
        return userRepository.findByCreatedAtAfter(since);
    }

    public Map<String, Long> getUserStatsByRole() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("SUPERADMIN", countByRole("SUPERADMIN"));
        stats.put("ADMIN", countByRole("ADMIN"));
        stats.put("ENDUSER", countByRole("ENDUSER"));
        stats.put("TOTAL", getTotalUserCount());
        return stats;
    }

    // ==================== INITIALIZATION ====================
    public void createInitialSuperAdmin() {
        // Check if any super admin exists
        if (userRepository.findByRole("SUPERADMIN").isEmpty()) {
            User superAdmin = new User();
            superAdmin.setUsername("superadmin");
            superAdmin.setPassword(passwordEncoder.encode("Admin@123"));
            superAdmin.setEmail("superadmin@ssoapp.com");
            superAdmin.setRole("SUPERADMIN");
            superAdmin.setCreatedBy("SYSTEM");
            superAdmin.setCreatedAt(LocalDateTime.now());
            superAdmin.setUpdatedAt(LocalDateTime.now());

            userRepository.save(superAdmin);
            logger.info("Initial Super Admin created - Username: superadmin, Password: Admin@123");
        }
    }

    // ==================== BATCH Operations ====================
    @Transactional
    public List<User> createBulkUsers(List<User> users, String createdBy) {
        List<User> createdUsers = new ArrayList<>();

        for (User user : users) {
            try {
                if (!existsByUsername(user.getUsername()) && !existsByEmail(user.getEmail())) {
                    user.setCreatedBy(createdBy);
                    user.setPassword(passwordEncoder.encode(user.getPassword()));
                    user.setCreatedAt(LocalDateTime.now());
                    user.setUpdatedAt(LocalDateTime.now());

                    User savedUser = userRepository.save(user);
                    createdUsers.add(savedUser);
                    logger.info("Bulk created user: {}", savedUser.getUsername());
                }
            } catch (Exception e) {
                logger.error("Failed to create user in bulk operation: {}", user.getUsername(), e);
            }
        }

        return createdUsers;
    }

    @Transactional
    public void updateBulkUsers(List<User> users) {
        for (User userUpdate : users) {
            try {
                if (userUpdate.getId() != null) {
                    updateUser(userUpdate.getId(), userUpdate);
                }
            } catch (Exception e) {
                logger.error("Failed to update user in bulk operation: {}", userUpdate.getId(), e);
            }
        }
    }

    // ==================== AUDIT Operations ====================
    public List<User> getUsersCreatedAfter(LocalDateTime date) {
        return userRepository.findByCreatedAtAfter(date);
    }

    public List<User> getUsersUpdatedAfter(LocalDateTime date) {
        return userRepository.findByUpdatedAtAfter(date);
    }

    public List<User> getInactiveUsers(int daysInactive) {
        LocalDateTime threshold = LocalDateTime.now().minusDays(daysInactive);
        return userRepository.findByUpdatedAtBefore(threshold);
    }
}