package com.ssoapp.repository;

import com.ssoapp.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ==================== Basic Queries ====================
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    // ==================== Role-based Queries ====================
    List<User> findByRole(String role);

    long countByRole(String role);

    @Query("SELECT u FROM User u WHERE u.role IN :roles")
    List<User> findByRoleIn(@Param("roles") List<String> roles);

    // ==================== Creator-based Queries ====================
    List<User> findByCreatedBy(String createdBy);

    long countByCreatedBy(String createdBy);

    // ==================== Date-based Queries ====================
    List<User> findByCreatedAtAfter(LocalDateTime date);

    List<User> findByCreatedAtBefore(LocalDateTime date);

    List<User> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    List<User> findByUpdatedAtAfter(LocalDateTime date);

    List<User> findByUpdatedAtBefore(LocalDateTime date);

    // ==================== Search Queries ====================
    List<User> findByUsernameContainingIgnoreCase(String username);

    List<User> findByEmailContainingIgnoreCase(String email);

    List<User> findByUsernameContainingOrEmailContaining(String username, String email);

    @Query("SELECT u FROM User u WHERE LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
            "OR LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<User> searchUsers(@Param("searchTerm") String searchTerm);

    // ==================== Complex Queries ====================
    @Query("SELECT u FROM User u WHERE u.role = :role AND u.createdBy = :createdBy")
    List<User> findByRoleAndCreatedBy(@Param("role") String role, @Param("createdBy") String createdBy);

    @Query("SELECT u FROM User u WHERE u.role = :role AND u.createdAt > :date")
    List<User> findRecentUsersByRole(@Param("role") String role, @Param("date") LocalDateTime date);

    @Query("SELECT COUNT(u) FROM User u WHERE u.role = :role AND u.createdAt > :date")
    long countRecentUsersByRole(@Param("role") String role, @Param("date") LocalDateTime date);

    // ==================== Statistics Queries ====================
    @Query("SELECT u.role, COUNT(u) FROM User u GROUP BY u.role")
    List<Object[]> getUserCountByRole();

    @Query("SELECT u.createdBy, COUNT(u) FROM User u GROUP BY u.createdBy")
    List<Object[]> getUserCountByCreator();

    @Query("SELECT DATE(u.createdAt), COUNT(u) FROM User u " +
            "WHERE u.createdAt > :startDate " +
            "GROUP BY DATE(u.createdAt) " +
            "ORDER BY DATE(u.createdAt)")
    List<Object[]> getUserCreationStats(@Param("startDate") LocalDateTime startDate);

    // ==================== Pagination Queries ====================
    @Query("SELECT u FROM User u WHERE u.role = :role ORDER BY u.createdAt DESC")
    List<User> findLatestUsersByRole(@Param("role") String role);

    @Query("SELECT u FROM User u ORDER BY u.createdAt DESC")
    List<User> findLatestUsers();

    // ==================== Admin Queries ====================
    @Query("SELECT u FROM User u WHERE u.role != 'SUPERADMIN' ORDER BY u.username")
    List<User> findAllNonSuperAdminUsers();

    @Query("SELECT u FROM User u WHERE u.role = 'ENDUSER' ORDER BY u.username")
    List<User> findAllEndUsers();

    // ==================== Validation Queries ====================
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.username = :username AND u.id != :userId")
    boolean existsByUsernameAndIdNot(@Param("username") String username, @Param("userId") Long userId);

    @Query("SELECT COUNT(u) > 0 FROM User u WHERE u.email = :email AND u.id != :userId")
    boolean existsByEmailAndIdNot(@Param("email") String email, @Param("userId") Long userId);

    // ==================== Cleanup Queries ====================
    void deleteByRole(String role);

    void deleteByCreatedAtBefore(LocalDateTime date);

    @Query("DELETE FROM User u WHERE u.role = :role AND u.createdAt < :date")
    void deleteOldUsersByRole(@Param("role") String role, @Param("date") LocalDateTime date);
}