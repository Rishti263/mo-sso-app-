package com.ssoapp.repository;

import com.ssoapp.entity.SSOConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface SSOConfigRepository extends JpaRepository<SSOConfig, Long> {
    Optional<SSOConfig> findBySsoType(String ssoType);
}