package com.ssoapp.controller;

import com.ssoapp.entity.SSOConfig;
import com.ssoapp.entity.User;
import com.ssoapp.service.SSOConfigService;
import com.ssoapp.service.UserService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Controller
@RequiredArgsConstructor
@Slf4j
public class JwtCallbackController {

    // Single accepted JWT callback prefix. Token may be appended directly after it, with or without a slash.
    private static final List<String> CALLBACK_PREFIXES = Collections.singletonList("/api/jwt/callback");

    private final SSOConfigService ssoConfigService;
    private final UserService userService;

    // ====== JWT Login Initiation ======
    @GetMapping("/sso/jwt/login")
    public String initiateJWTLogin() {
        final String rid = rid();
        log.info("[{}] === JWT Login Initiation START ===", rid);
        
        Optional<SSOConfig> cfgOpt = ssoConfigService.getConfigByType("JWT");
        if (!cfgOpt.isPresent()) {
            log.error("[{}] JWT login aborted: config not found in database", rid);
            return "redirect:/login?error=jwt_not_configured";
        }
        
        SSOConfig cfg = cfgOpt.get();
        log.info("[{}] JWT config retrieved from DB:", rid);
        log.info("[{}]   - ID: {}", rid, cfg.getId());
        log.info("[{}]   - SSO Type: {}", rid, cfg.getSsoType());
        log.info("[{}]   - Enabled: {}", rid, cfg.getIsEnabled());
        log.info("[{}]   - IDP URL: {}", rid, cfg.getIdpUrl());
        log.info("[{}]   - Client ID: {}", rid, cfg.getClientId());
        log.info("[{}]   - Entity ID: {}", rid, cfg.getEntityId());
        log.info("[{}]   - Client Secret present: {}", rid, hasText(cfg.getClientSecret()));
        
        // Check if enabled
        if (!Boolean.TRUE.equals(cfg.getIsEnabled())) {
            log.error("[{}] JWT login aborted: config is disabled (isEnabled={})", rid, cfg.getIsEnabled());
            return "redirect:/login?error=jwt_disabled";
        }
        
        // Check if IDP URL is present
        if (!hasText(cfg.getIdpUrl())) {
            log.error("[{}] JWT login aborted: IDP URL is empty or null", rid);
            return "redirect:/login?error=jwt_not_configured";
        }
        
        log.info("[{}] All validations passed. Redirecting to IdP: {}", rid, cfg.getIdpUrl());
        log.info("[{}] === JWT Login Initiation END ===", rid);
        return "redirect:" + cfg.getIdpUrl();
    }

    // Regex-tail mapping covers "…/sso/jwt/callback<token>" and "…/sso/jwt/callback/<token>"
    @GetMapping("/api/jwt/callback**")
    public void jwtCallbackGet(HttpServletRequest req, HttpServletResponse res) throws Exception {
        handleCallback(req, res);
    }

    @PostMapping("/api/jwt/callback**")
    public void jwtCallbackPost(HttpServletRequest req, HttpServletResponse res) throws Exception {
        handleCallback(req, res);
    }

    // ====== Core JWT Callback Flow (HS256 only) ======
    private void handleCallback(HttpServletRequest req, HttpServletResponse res) throws Exception {
        final String rid = rid();
        final long t0 = System.currentTimeMillis();

        log.info("[{}] === JWT Callback START ===", rid);
        log.info("[{}] URI={} QS={} SessionPresent={}", rid, req.getRequestURI(), req.getQueryString(), req.getSession(false) != null);

        Optional<SSOConfig> cfgOpt = ssoConfigService.getConfigByType("JWT");
        if (!cfgOpt.isPresent() || !Boolean.TRUE.equals(cfgOpt.get().getIsEnabled())) {
            log.warn("[{}] Config missing/disabled", rid);
            res.sendRedirect("/login?error=jwt_disabled");
            return;
        }
        SSOConfig cfg = cfgOpt.get();

        // 1) Token extraction
        String token = extractToken(req);
        if (!hasText(token)) {
            log.warn("[{}] No token found in request", rid);
            res.sendRedirect("/login?error=missing_token");
            return;
        }
        log.info("[{}] Token extracted: len={} prefix={}", rid, token.length(), token.substring(0, Math.min(20, token.length())));

        // 2) Resolve HS256 key from clientSecret (RAW-first)
        SecretKey hsKey;
        try {
            hsKey = resolveHmacKeyRawFirst(cfg.getClientSecret());
            log.info("[{}] HS256 key resolved from clientSecret", rid);
        } catch (IllegalArgumentException ex) {
            log.error("[{}] HS256 key resolution failed: {}", rid, ex.getMessage());
            res.sendRedirect("/login?error=jwt_validation_failed");
            return;
        }

        // 3) Parse + signature verify + optional iss/aud checks (iss=entityId, aud=clientId)
        Claims claims;
        try {
            claims = parseJwtHs256(token, hsKey);
            log.info("[{}] JWT parsed; validating claims", rid);
            validateStandardClaims(claims, cfg.getEntityId(), cfg.getClientId());
        } catch (ExpiredJwtException ex) {
            log.warn("[{}] JWT expired: {}", rid, ex.getMessage());
            res.sendRedirect("/login?error=jwt_expired");
            return;
        } catch (SignatureException ex) {
            log.warn("[{}] JWT signature invalid: {}", rid, ex.getMessage());
            res.sendRedirect("/login?error=jwt_signature_invalid");
            return;
        } catch (Exception ex) {
            log.error("[{}] JWT validation failed: {} ({})", rid, ex.getMessage(), ex.getClass().getSimpleName());
            res.sendRedirect("/login?error=jwt_validation_failed");
            return;
        }
        log.info("[{}] Claims OK: iss={} aud={} sub={}", rid, claims.getIssuer(), claims.get("aud"), claims.getSubject());

        // 4) Identity hydration
        String email = coalesce(claims.get("email", String.class), claims.getSubject());
        if (!hasText(email)) {
            log.warn("[{}] Missing email/subject", rid);
            res.sendRedirect("/login?error=invalid_token");
            return;
        }
        String username = coalesce(
                claims.get("username", String.class),
                email.contains("@") ? email.substring(0, email.indexOf('@')) : email
        );
        String firstName = coalesce(claims.get("first_name", String.class), claims.get("given_name", String.class));
        String lastName  = coalesce(claims.get("last_name", String.class),  claims.get("family_name", String.class));
        String displayName = ((firstName != null ? firstName : "") + " " + (lastName != null ? lastName : "")).trim();

        log.info("[{}] Identity resolved: email={} username={} name='{}'", rid, email, username, displayName);

        // 5) Authorities (normalize; always baseline ROLE_ENDUSER)
        List<String> roleHints = extractRoles(claims);
        List<SimpleGrantedAuthority> authorities = normalizeAuthorities(roleHints);
        log.info("[{}] Authorities: {}", rid, authorities);

        // 6) Upsert user
        User user = userService.findByUsername(username).orElseGet(() -> {
            log.info("[{}] Creating user '{}'", rid, username);
            User u = new User();
            u.setUsername(username);
            u.setEmail(email);
            u.setPassword("SSO_USER");
            u.setRole("ENDUSER");
            return userService.registerUser(u);
        });

        // 7) Security context
        req.getSession(true);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(email, null, authorities);

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);

        HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
        repository.saveContext(ctx, req, res);

        req.getSession().setAttribute("user", user); // ← Required for dashboard session validation
        req.getSession().setAttribute("userEmail", user.getEmail());
        req.getSession().setAttribute("userName", hasText(displayName) ? displayName : (hasText(username) ? username : "SSO User"));
        req.getSession().setAttribute("SPRING_SECURITY_CONTEXT", ctx);

        // 8) Role-based landing to align with SecurityConfig; avoids / -> /login redirects
        String landing = resolveLanding(auth);
        log.info("[{}] Redirecting to landing: {}", rid, landing);

        res.reset();
        res.setStatus(HttpServletResponse.SC_FOUND);
        res.setHeader("Location", landing);
        res.flushBuffer();

        log.info("[{}] === JWT Callback END ({} ms) ===", rid, (System.currentTimeMillis() - t0));
    }

    // ====== JWT Utilities ======
    private Claims parseJwtHs256(String token, SecretKey key) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new MalformedJwtException("Invalid JWT structure");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        if (!headerJson.contains("\"alg\":\"HS256\"")) {
            throw new JwtException("Unexpected alg; only HS256 is allowed");
        }
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Issuer → entityId, Audience → clientId (if provided)
    private void validateStandardClaims(Claims c, String expectedIssuer, String expectedAudience) {
        if (hasText(expectedIssuer)) {
            if (!expectedIssuer.equals(c.getIssuer())) throw new JwtException("unexpected issuer");
        }
        if (hasText(expectedAudience)) {
            Object aud = c.get("aud");
            if (aud instanceof String) {
                if (!expectedAudience.equals(aud)) throw new JwtException("unexpected audience");
            } else if (aud instanceof Collection) {
                if (!((Collection<?>) aud).contains(expectedAudience)) throw new JwtException("unexpected audience");
            }
        }
    }

    /**
     * RAW-first HS256 key derivation using SSOConfig.clientSecret.
     * 1) RAW UTF-8 bytes if length >= 32 (e.g., LUxkIhkbfeM4Ieuf5UpUsDyGmQqSXyd2 → 32 bytes)
     * 2) Base64URL-decoded if >= 32
     * 3) Base64-decoded if >= 32
     */
    private SecretKey resolveHmacKeyRawFirst(String secretFromDb) {
        if (!hasText(secretFromDb)) throw new IllegalArgumentException("Missing HS256 secret");
        String s = secretFromDb.trim();

        byte[] raw = s.getBytes(StandardCharsets.UTF_8);
        if (raw.length >= 32) return Keys.hmacShaKeyFor(raw);

        byte[] b64url = tryBase64UrlDecode(s);
        if (b64url != null && b64url.length >= 32) return Keys.hmacShaKeyFor(b64url);

        byte[] b64 = tryBase64Decode(s);
        if (b64 != null && b64.length >= 32) return Keys.hmacShaKeyFor(b64);

        throw new IllegalArgumentException("HS256 key must be >= 32 bytes (raw or decoded)");
    }

    private byte[] tryBase64UrlDecode(String s) {
        try {
            String normalized = s.replace('-', '+').replace('_', '/');
            int pad = (4 - (normalized.length() % 4)) % 4;
            if (pad > 0) normalized = normalized + "====".substring(0, pad);
            return Decoders.BASE64.decode(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private byte[] tryBase64Decode(String s) {
        try {
            String normalized = s;
            int pad = (4 - (normalized.length() % 4)) % 4;
            if (pad > 0) normalized = normalized + "====".substring(0, pad);
            return Decoders.BASE64.decode(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    // ====== Token + Role Helpers ======
    private String extractToken(HttpServletRequest req) {
        String rid = rid();

        String token = req.getParameter("id_token");
        if (hasText(token)) {
            log.info("[{}] Token from query param id_token", rid);
            return token;
        }

        token = req.getParameter("token");
        if (hasText(token)) {
            log.info("[{}] Token from query param token", rid);
            return token;
        }

        String authHeader = req.getHeader("Authorization");
        if (hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            log.info("[{}] Token from Authorization header", rid);
            return authHeader.substring(7);
        }

        String uri = req.getRequestURI();
        if (hasText(uri)) {
            for (String prefix : CALLBACK_PREFIXES) {
                if (uri.startsWith(prefix)) {
                    String trailing = uri.substring(prefix.length()); // "" | "<token>" | "/<token>"
                    if (!hasText(trailing)) continue;
                    if (trailing.startsWith("/")) trailing = trailing.substring(1);
                    if (hasText(trailing)) {
                        log.info("[{}] Token from path after {}", rid, prefix);
                        return trailing;
                    }
                }
            }
        }
        return null;
    }

    private List<String> extractRoles(Claims claims) {
        List<String> out;

        Object role = claims.get("role");
        if (role instanceof String) {
            String s = ((String) role).trim();
            if (!s.isEmpty()) {
                out = new ArrayList<>(1);
                out.add(s);
                return out;
            }
        }

        Object roles = claims.get("roles");
        if (roles instanceof Collection) {
            Collection<?> c = (Collection<?>) roles;
            out = new ArrayList<>(c.size());
            for (Object o : c) {
                if (o == null) continue;
                String s = o.toString().trim();
                if (s.isEmpty()) continue;
                out.add(s);
            }
            if (!out.isEmpty()) return out;
        }

        Object groups = claims.get("groups");
        if (groups instanceof Collection) {
            Collection<?> c2 = (Collection<?>) groups;
            out = new ArrayList<>(c2.size());
            for (Object o : c2) {
                if (o == null) continue;
                String s = o.toString().trim();
                if (s.isEmpty()) continue;
                out.add(s);
            }
            if (!out.isEmpty()) return out;
        }

        return Collections.emptyList();
    }

    private List<SimpleGrantedAuthority> normalizeAuthorities(List<String> hints) {
        List<SimpleGrantedAuthority> out = new ArrayList<>();
        // Baseline to satisfy /user/** in SecurityConfig
        out.add(new SimpleGrantedAuthority("ROLE_ENDUSER"));

        if (hints != null) {
            for (String r : hints) {
                if (r == null) continue;
                String role = r.trim();
                if (role.isEmpty()) continue;

                String upper = role.toUpperCase(Locale.ROOT);
                switch (upper) {
                    case "ENDUSER", "USER", "DEFAULT", "XECURIFY", "APIGROUP" -> {
                        // baseline already in place
                    }
                    case "ADMIN" -> out.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    case "SUPERADMIN" -> out.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));
                    default -> {
                        if (!upper.startsWith("ROLE_")) {
                            out.add(new SimpleGrantedAuthority("ROLE_" + upper));
                        } else {
                            out.add(new SimpleGrantedAuthority(upper));
                        }
                    }
                }
            }
        }
        return out;
    }

    private String resolveLanding(UsernamePasswordAuthenticationToken auth) {
        boolean superadmin = auth.getAuthorities().stream().anyMatch(a -> "ROLE_SUPERADMIN".equals(a.getAuthority()));
        if (superadmin) return "/superadmin/dashboard";

        boolean admin = auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        if (admin) return "/admin/dashboard";

        return "/user/dashboard";
    }

    // ====== Small utils ======
    private boolean hasText(String s) {
        return s != null && !s.trim().isEmpty();
    }
    private String nz(String s) {
        return s == null ? "" : s;
    }
    private String coalesce(String a, String b) {
        return hasText(a) ? a : (hasText(b) ? b : null);
    }
    private static String rid() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
