package com.ssoapp.controller;

import com.ssoapp.entity.SSOConfig;
import com.ssoapp.service.SSOConfigService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/sso")
@RequiredArgsConstructor
@Slf4j
public class SSOConfigController {

    private final SSOConfigService ssoConfigService;

    // ====== JWT Configuration ======
    @PostMapping("/jwt/config")
    public ResponseEntity<Map<String, Object>> saveJwtConfig(@RequestBody JwtConfigRequest request) {
        log.info("Received JWT config save request: idpUrl={}, clientId={}, enabled={}", 
                 request.getIdpUrl(), request.getClientId(), request.isEnabled());
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Get existing config if any
            Optional<SSOConfig> existingOpt = ssoConfigService.getConfigByType("JWT");
            SSOConfig config;
            
            if (existingOpt.isPresent()) {
                config = existingOpt.get();
                log.info("Updating existing JWT config with id={}", config.getId());
            } else {
                config = new SSOConfig();
                config.setSsoType("JWT");
                log.info("Creating new JWT config");
            }
            
            // Update fields
            config.setIdpUrl(request.getIdpUrl());
            config.setClientId(request.getClientId());
            
            // Only update secret if it's not masked (dots)
            if (request.getClientSecret() != null && 
                !request.getClientSecret().matches("•+") &&
                !request.getClientSecret().matches("\\.+")) {
                config.setClientSecret(request.getClientSecret());
                log.info("Client secret updated");
            } else {
                log.info("Client secret unchanged (masked value received)");
            }
            
            config.setIsEnabled(request.isEnabled());
            
            // Set entityId same as clientId for JWT validation
            config.setEntityId(request.getClientId());
            
            // Save
            SSOConfig saved = ssoConfigService.saveOrUpdateConfig(config);
            log.info("JWT config saved successfully with id={}", saved.getId());
            
            response.put("success", true);
            response.put("message", "JWT configuration saved successfully");
            response.put("id", saved.getId());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to save JWT config", e);
            response.put("success", false);
            response.put("message", "Failed to save JWT configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/jwt/config")
    public ResponseEntity<?> getJwtConfig() {
        log.info("Fetching JWT config");
        
        try {
            Optional<SSOConfig> configOpt = ssoConfigService.getConfigByType("JWT");
            
            if (configOpt.isPresent()) {
                SSOConfig config = configOpt.get();
                log.info("Found JWT config with id={}", config.getId());
                
                JwtConfigRequest response = new JwtConfigRequest();
                response.setIdpUrl(config.getIdpUrl());
                response.setClientId(config.getClientId());
                response.setClientSecret("••••••••••••••••••••"); // Mask the secret
                response.setEnabled(config.getIsEnabled() != null && config.getIsEnabled());
                
                return ResponseEntity.ok(response);
            } else {
                log.info("No JWT config found, returning empty");
                JwtConfigRequest response = new JwtConfigRequest();
                response.setEnabled(false);
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            log.error("Failed to fetch JWT config", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to fetch JWT configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    // ====== SAML Configuration ======
    @PostMapping("/saml/config")
    public ResponseEntity<Map<String, Object>> saveSamlConfig(@RequestBody SamlConfigRequest request) {
        log.info("Received SAML config save request: entityId={}, ssoUrl={}, enabled={}", 
                 request.getEntityId(), request.getSsoUrl(), request.isEnabled());
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            Optional<SSOConfig> existingOpt = ssoConfigService.getConfigByType("SAML");
            SSOConfig config;
            
            if (existingOpt.isPresent()) {
                config = existingOpt.get();
            } else {
                config = new SSOConfig();
                config.setSsoType("SAML");
            }
            
            config.setEntityId(request.getEntityId());
            config.setSsoUrl(request.getSsoUrl());
            config.setCertificate(request.getCertificate());
            config.setIsEnabled(request.isEnabled());
            
            SSOConfig saved = ssoConfigService.saveOrUpdateConfig(config);
            log.info("SAML config saved successfully with id={}", saved.getId());
            
            response.put("success", true);
            response.put("message", "SAML configuration saved successfully");
            response.put("id", saved.getId());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to save SAML config", e);
            response.put("success", false);
            response.put("message", "Failed to save SAML configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/saml/config")
    public ResponseEntity<?> getSamlConfig() {
        log.info("Fetching SAML config");
        
        try {
            Optional<SSOConfig> configOpt = ssoConfigService.getConfigByType("SAML");
            
            if (configOpt.isPresent()) {
                SSOConfig config = configOpt.get();
                
                SamlConfigRequest response = new SamlConfigRequest();
                response.setEntityId(config.getEntityId());
                response.setSsoUrl(config.getSsoUrl());
                response.setCertificate(config.getCertificate());
                response.setEnabled(config.getIsEnabled() != null && config.getIsEnabled());
                
                return ResponseEntity.ok(response);
            } else {
                SamlConfigRequest response = new SamlConfigRequest();
                response.setEnabled(false);
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            log.error("Failed to fetch SAML config", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to fetch SAML configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    // ====== OAuth Configuration ======
    @PostMapping("/oauth/config")
    public ResponseEntity<Map<String, Object>> saveOauthConfig(@RequestBody OauthConfigRequest request) {
        log.info("Received OAuth config save request: idpUrl={}, ssoUrl={}, enabled={}", 
                 request.getIdpUrl(), request.getSsoUrl(), request.isEnabled());
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            Optional<SSOConfig> existingOpt = ssoConfigService.getConfigByType("OAUTH");
            SSOConfig config;
            
            if (existingOpt.isPresent()) {
                config = existingOpt.get();
            } else {
                config = new SSOConfig();
                config.setSsoType("OAUTH");
            }
            
            config.setIdpUrl(request.getIdpUrl());
            config.setSsoUrl(request.getSsoUrl());
            config.setClientId(request.getClientId());
            
            // Only update secret if not masked
            if (request.getClientSecret() != null && 
                !request.getClientSecret().matches("•+") &&
                !request.getClientSecret().matches("\\.+")) {
                config.setClientSecret(request.getClientSecret());
            }
            
            config.setIsEnabled(request.isEnabled());
            
            SSOConfig saved = ssoConfigService.saveOrUpdateConfig(config);
            log.info("OAuth config saved successfully with id={}", saved.getId());
            
            response.put("success", true);
            response.put("message", "OAuth configuration saved successfully");
            response.put("id", saved.getId());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to save OAuth config", e);
            response.put("success", false);
            response.put("message", "Failed to save OAuth configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/oauth/config")
    public ResponseEntity<?> getOauthConfig() {
        log.info("Fetching OAuth config");
        
        try {
            Optional<SSOConfig> configOpt = ssoConfigService.getConfigByType("OAUTH");
            
            if (configOpt.isPresent()) {
                SSOConfig config = configOpt.get();
                
                OauthConfigRequest response = new OauthConfigRequest();
                response.setIdpUrl(config.getIdpUrl());
                response.setSsoUrl(config.getSsoUrl());
                response.setClientId(config.getClientId());
                response.setClientSecret("••••••••••••••••••••"); // Mask
                response.setEnabled(config.getIsEnabled() != null && config.getIsEnabled());
                
                return ResponseEntity.ok(response);
            } else {
                OauthConfigRequest response = new OauthConfigRequest();
                response.setEnabled(false);
                return ResponseEntity.ok(response);
            }
            
        } catch (Exception e) {
            log.error("Failed to fetch OAuth config", e);
            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to fetch OAuth configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    // ====== DTOs ======
    @Data
    public static class JwtConfigRequest {
        private String idpUrl;
        private String clientId;
        private String clientSecret;
        private boolean enabled;
    }

    @Data
    public static class SamlConfigRequest {
        private String entityId;
        private String ssoUrl;
        private String certificate;
        private boolean enabled;
    }

    @Data
    public static class OauthConfigRequest {
        private String idpUrl;
        private String ssoUrl;
        private String clientId;
        private String clientSecret;
        private boolean enabled;
    }
}
