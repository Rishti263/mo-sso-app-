package com.ssoapp.service;

import com.ssoapp.entity.SSOConfig;
import com.ssoapp.repository.SSOConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class SSOConfigService {

    private final SSOConfigRepository ssoConfigRepository;

    public SSOConfig saveOrUpdateConfig(SSOConfig config) {
        Optional<SSOConfig> existing = ssoConfigRepository.findBySsoType(config.getSsoType());
        if (existing.isPresent()) {
            config.setId(existing.get().getId());
        }
        return ssoConfigRepository.save(config);
    }

    public Optional<SSOConfig> getConfigByType(String ssoType) {
        return ssoConfigRepository.findBySsoType(ssoType);
    }
}