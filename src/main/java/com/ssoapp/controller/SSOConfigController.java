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

    // ====== DIAGNOSTIC ENDPOINT ======
    @GetMapping("/config/debug")
    public ResponseEntity<?> debugAllConfigs() {
        log.info("=== DEBUG: Fetching all SSO configs ===");
        
        Map<String, Object> debug = new HashMap<>();
        
        // JWT Config
        Optional<SSOConfig> jwtOpt = ssoConfigService.getConfigByType("JWT");
        if (jwtOpt.isPresent()) {
            SSOConfig jwt = jwtOpt.get();
            Map<String, Object> jwtDebug = new HashMap<>();
            jwtDebug.put("id", jwt.getId());
            jwtDebug.put("ssoType", jwt.getSsoType());
            jwtDebug.put("isEnabled", jwt.getIsEnabled());
            jwtDebug.put("idpUrl", jwt.getIdpUrl());
            jwtDebug.put("clientId", jwt.getClientId());
            jwtDebug.put("entityId", jwt.getEntityId());
            jwtDebug.put("hasClientSecret", jwt.getClientSecret() != null && !jwt.getClientSecret().isEmpty());
            debug.put("JWT", jwtDebug);
        } else {
            debug.put("JWT", "NOT_FOUND");
        }
        
        // OAuth Config
        Optional<SSOConfig> oauthOpt = ssoConfigService.getConfigByType("OAUTH");
        if (oauthOpt.isPresent()) {
            SSOConfig oauth = oauthOpt.get();
            Map<String, Object> oauthDebug = new HashMap<>();
            oauthDebug.put("id", oauth.getId());
            oauthDebug.put("ssoType", oauth.getSsoType());
            oauthDebug.put("isEnabled", oauth.getIsEnabled());
            oauthDebug.put("idpUrl", oauth.getIdpUrl());
            oauthDebug.put("ssoUrl", oauth.getSsoUrl());
            oauthDebug.put("clientId", oauth.getClientId());
            oauthDebug.put("hasClientSecret", oauth.getClientSecret() != null && !oauth.getClientSecret().isEmpty());
            debug.put("OAUTH", oauthDebug);
        } else {
            debug.put("OAUTH", "NOT_FOUND");
        }
        
        // SAML Config
        Optional<SSOConfig> samlOpt = ssoConfigService.getConfigByType("SAML");
        if (samlOpt.isPresent()) {
            SSOConfig saml = samlOpt.get();
            Map<String, Object> samlDebug = new HashMap<>();
            samlDebug.put("id", saml.getId());
            samlDebug.put("ssoType", saml.getSsoType());
            samlDebug.put("isEnabled", saml.getIsEnabled());
            samlDebug.put("entityId", saml.getEntityId());
            samlDebug.put("ssoUrl", saml.getSsoUrl());
            samlDebug.put("hasCertificate", saml.getCertificate() != null && !saml.getCertificate().isEmpty());
            debug.put("SAML", samlDebug);
        } else {
            debug.put("SAML", "NOT_FOUND");
        }
        
        log.info("=== DEBUG OUTPUT: {} ===", debug);
        return ResponseEntity.ok(debug);
    }

    // ====== JWT Configuration ======
    @PostMapping("/jwt/config")
    public ResponseEntity<Map<String, Object>> saveJwtConfig(@RequestBody JwtConfigRequest request) {
        log.info("=== JWT Config Save Request ===");
        log.info("idpUrl: {}", request.getIdpUrl());
        log.info("clientId: {}", request.getClientId());
        log.info("clientSecret (masked): {}...", request.getClientSecret() != null && request.getClientSecret().length() > 4 
                 ? request.getClientSecret().substring(0, 4) : "null");
        log.info("enabled: {}", request.isEnabled());
        
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
            
            // Only update secret if it's not masked (dots or bullets)
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
            log.info("=== JWT config saved successfully ===");
            log.info("Saved config details:");
            log.info("  - id: {}", saved.getId());
            log.info("  - ssoType: {}", saved.getSsoType());
            log.info("  - isEnabled: {}", saved.getIsEnabled());
            log.info("  - idpUrl: {}", saved.getIdpUrl());
            log.info("  - clientId: {}", saved.getClientId());
            log.info("  - entityId: {}", saved.getEntityId());
            log.info("  - has clientSecret: {}", saved.getClientSecret() != null && !saved.getClientSecret().isEmpty());
            
            response.put("success", true);
            response.put("message", "JWT configuration saved successfully");
            response.put("id", saved.getId());
            response.put("config", Map.of(
                "id", saved.getId(),
                "ssoType", saved.getSsoType(),
                "isEnabled", saved.getIsEnabled(),
                "idpUrl", saved.getIdpUrl(),
                "clientId", saved.getClientId()
            ));
            
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
                log.info("Found JWT config with id={}, enabled={}, idpUrl={}", 
                         config.getId(), config.getIsEnabled(), config.getIdpUrl());
                
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
            
            // Set entityId same as clientId for validation (optional)
            config.setEntityId(request.getClientId());
            
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
