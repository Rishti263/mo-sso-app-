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
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Controller
@RequestMapping("/sso/oauth")
@RequiredArgsConstructor
@Slf4j
public class OAuthSSOController {

    private static final String CALLBACK_URL = "http://localhost:8080/sso/oauth/callback";
    private final RestTemplate rest = new RestTemplate();

    private final SSOConfigService ssoConfigService;
    private final UserService userService;

    // ===== Login kick-off =====
    @GetMapping("/login")
    public String initiateOAuthLogin(HttpSession session) {
        final String rid = rid();
        Optional<SSOConfig> cfgOpt = ssoConfigService.getConfigByType("OAUTH");
        if (!cfgOpt.isPresent() || !Boolean.TRUE.equals(cfgOpt.get().getIsEnabled())) {
            log.warn("[{}] OAuth not configured/enabled", rid);
            return "redirect:/login?error=oauth_not_configured";
        }
        SSOConfig cfg = cfgOpt.get();
        if (!hasText(cfg.getIdpUrl()) || !hasText(cfg.getClientId()) || !hasText(cfg.getSsoUrl())) {
            log.warn("[{}] OAuth config incomplete", rid);
            return "redirect:/login?error=oauth_not_configured";
        }

        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth_state", state);

        try {
            String authUrl =
                    cfg.getIdpUrl()
                            + "?response_type=code"
                            + "&client_id=" + URLEncoder.encode(cfg.getClientId(), StandardCharsets.UTF_8.name())
                            + "&redirect_uri=" + URLEncoder.encode(CALLBACK_URL, StandardCharsets.UTF_8.name())
                            + "&scope=" + URLEncoder.encode("openid profile email", StandardCharsets.UTF_8.name())
                            + "&state=" + state;

            log.info("[{}] Redirecting to OAuth Authorization: {}", rid, authUrl);
            return "redirect:" + authUrl;
        } catch (Exception e) {
            log.error("[{}] OAuth auth URL build failed", rid, e);
            return "redirect:/login?error=oauth_init_failed";
        }
    }

    // ===== Authorization Code callback (GET) =====
    @GetMapping("/callback")
    public void oauthCallback(
            String code,
            String state,
            String error,
            String error_description,
            HttpServletRequest req,
            HttpServletResponse res
    ) throws Exception {
        final String rid = rid();
        final long t0 = System.currentTimeMillis();
        log.info("[{}] === OAuth Callback START === code?={} state={} error={} desc={}",
                rid, code != null, state, error, error_description);

        HttpSession session = req.getSession(false);

        try {
            if (error != null) {
                log.warn("[{}] Provider error: {} - {}", rid, error, error_description);
                res.sendRedirect("/login?error=oauth_" + error);
                return;
            }
            if (session == null) {
                log.warn("[{}] Session lost before callback; state={}", rid, state);
                res.sendRedirect("/login?error=oauth_session_lost");
                return;
            }
            String sessionState = (String) session.getAttribute("oauth_state");
            if (!hasText(sessionState) || !sessionState.equals(state)) {
                log.warn("[{}] State mismatch: session={} received={}", rid, sessionState, state);
                res.sendRedirect("/login?error=oauth_invalid_state");
                return;
            }
            if (!hasText(code)) {
                log.warn("[{}] Missing authorization code", rid);
                res.sendRedirect("/login?error=oauth_missing_code");
                return;
            }

            Optional<SSOConfig> cfgOpt = ssoConfigService.getConfigByType("OAUTH");
            if (!cfgOpt.isPresent() || !Boolean.TRUE.equals(cfgOpt.get().getIsEnabled())) {
                log.warn("[{}] OAuth not configured/enabled at callback", rid);
                res.sendRedirect("/login?error=oauth_not_configured");
                return;
            }
            SSOConfig cfg = cfgOpt.get();

            // Exchange code -> tokens
            Map<String, Object> tokenResponse = exchangeCodeForToken(code, cfg);
            if (tokenResponse == null) {
                log.warn("[{}] Token exchange returned null", rid);
                res.sendRedirect("/login?error=oauth_token_null");
                return;
            }
            log.info("[{}] Token keys: {}", rid, tokenResponse.keySet());

            // We require id_token (JWT) to avoid a UserInfo call
            Object idt = tokenResponse.get("id_token");
            if (!(idt instanceof String) || !hasText((String) idt)) {
                log.warn("[{}] Missing id_token in token response", rid);
                res.sendRedirect("/login?error=oauth_no_id_token");
                return;
            }
            String idToken = (String) idt;

            // HS256 validation using clientSecret
            SecretKey key;
            try {
                key = resolveHmacKeyRawFirst(cfg.getClientSecret());
            } catch (IllegalArgumentException e) {
                log.error("[{}] HS256 key resolution failed: {}", rid, e.getMessage());
                res.sendRedirect("/login?error=oauth_key_invalid");
                return;
            }

            Claims claims;
            try {
                claims = parseJwtHs256(idToken, key);
                validateStandardClaims(claims, cfg.getEntityId(), cfg.getClientId()); // iss=entityId, aud=clientId (if set)
            } catch (ExpiredJwtException ex) {
                log.warn("[{}] id_token expired", rid, ex);
                res.sendRedirect("/login?error=oauth_token_expired");
                return;
            } catch (SignatureException ex) {
                log.warn("[{}] id_token signature invalid", rid, ex);
                res.sendRedirect("/login?error=oauth_signature_invalid");
                return;
            } catch (JwtException ex) {
                log.warn("[{}] id_token validation failed: {}", rid, ex.getMessage());
                res.sendRedirect("/login?error=oauth_idtoken_invalid");
                return;
            }

            // Identity hydration
            String email = coalesce(claims.get("email", String.class), claims.getSubject());
            if (!hasText(email)) {
                log.warn("[{}] Missing email/subject in id_token", rid);
                res.sendRedirect("/login?error=oauth_missing_identity");
                return;
            }
            String username = coalesce(
                    claims.get("preferred_username", String.class),
                    claims.get("username", String.class),
                    email.contains("@") ? email.substring(0, email.indexOf('@')) : email
            );
            String firstName = coalesce(claims.get("given_name", String.class), claims.get("first_name", String.class));
            String lastName  = coalesce(claims.get("family_name", String.class), claims.get("last_name", String.class));
            String displayName = ((firstName != null ? firstName : "") + " " + (lastName != null ? lastName : "")).trim();
            log.info("[{}] OAuth identity: email={} username={} name='{}'", rid, email, username, displayName);

            // Roles
            List<String> roleHints = extractRoleHints(claims);
            List<SimpleGrantedAuthority> authorities = normalizeAuthorities(roleHints);
            log.info("[{}] Authorities: {}", rid, authorities);

            // Upsert user
            User user = userService.findByUsername(username).orElseGet(() -> {
                User u = new User();
                u.setUsername(username);
                u.setEmail(email);
                u.setPassword(""); // external SSO
                u.setRole("ENDUSER");
                u.setCreatedBy("OAUTH_SSO");
                return userService.registerUser(u);
            });

            // Security context + session
            req.getSession(true);
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(email, null, authorities);

            SecurityContext ctx = SecurityContextHolder.createEmptyContext();
            ctx.setAuthentication(auth);
            SecurityContextHolder.setContext(ctx);

            HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
            repo.saveContext(ctx, req, res);

            req.getSession().setAttribute("user", user);
            req.getSession().setAttribute("userEmail", user.getEmail());
            req.getSession().setAttribute("userName", hasText(displayName) ? displayName : username);
            req.getSession().setAttribute("SPRING_SECURITY_CONTEXT", ctx);

            // Landing
            String landing = resolveLanding(auth);
            log.info("[{}] Redirecting to landing: {}", rid, landing);
            res.sendRedirect(landing);
        } catch (Exception e) {
            log.error("[{}] OAuth callback exception", rid, e);
            res.sendRedirect("/login?error=oauth_exception");
        } finally {
            if (session != null) session.removeAttribute("oauth_state");
            log.info("[{}] === OAuth Callback END ({} ms) ===", rid, (System.currentTimeMillis() - t0));
        }
    }

    // ===== Token exchange =====
    @SuppressWarnings("unchecked")
    private Map<String, Object> exchangeCodeForToken(String code, SSOConfig cfg) {
        final String rid = rid();
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "authorization_code");
            form.add("code", code);
            form.add("redirect_uri", CALLBACK_URL);
            form.add("client_id", cfg.getClientId());
            form.add("client_secret", cfg.getClientSecret());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            // Some providers require Basic and ignore body client creds; harmless if not needed
            headers.setBasicAuth(cfg.getClientId(), cfg.getClientSecret());

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
            log.info("[{}] Token POST → {}", rid, cfg.getSsoUrl());

            ResponseEntity<Map> resp = rest.exchange(cfg.getSsoUrl(), HttpMethod.POST, entity, Map.class);
            log.info("[{}] Token exchange status: {}", rid, resp.getStatusCode());
            return resp.getBody();
        } catch (HttpClientErrorException e) {
            log.error("[{}] Token exchange HTTP {} body={}", rid, e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("[{}] Token exchange failure", rid, e);
            return null;
        }
    }

    // ===== JWT utils (HS256 only) =====
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

    // iss → entityId, aud → clientId (if configured)
    private void validateStandardClaims(Claims c, String expectedIssuer, String expectedAudience) {
        if (hasText(expectedIssuer)) {
            String iss = c.getIssuer();
            if (!expectedIssuer.equals(iss)) throw new JwtException("unexpected issuer");
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

    // ===== Role and landing =====
    private List<String> extractRoleHints(Claims claims) {
        List<String> out;

        Object role = claims.get("role");
        if (role instanceof String) {
            String s = ((String) role).trim();
            if (!s.isEmpty()) return Collections.singletonList(s);
        }

        Object roles = claims.get("roles");
        if (roles instanceof Collection) {
            out = new ArrayList<>();
            for (Object o : (Collection<?>) roles) {
                if (o == null) continue;
                String s = o.toString().trim();
                if (!s.isEmpty()) out.add(s);
            }
            if (!out.isEmpty()) return out;
        }

        Object groups = claims.get("groups");
        if (groups instanceof Collection) {
            out = new ArrayList<>();
            for (Object o : (Collection<?>) groups) {
                if (o == null) continue;
                String s = o.toString().trim();
                if (!s.isEmpty()) out.add(s);
            }
            if (!out.isEmpty()) return out;
        }

        return Collections.emptyList();
    }

    private List<SimpleGrantedAuthority> normalizeAuthorities(List<String> hints) {
        List<SimpleGrantedAuthority> out = new ArrayList<>();
        out.add(new SimpleGrantedAuthority("ROLE_ENDUSER"));
        if (hints != null) {
            for (String r : hints) {
                if (r == null) continue;
                String role = r.trim();
                if (role.isEmpty()) continue;
                String upper = role.toUpperCase(Locale.ROOT);
                switch (upper) {
                    case "ENDUSER":
                    case "USER":
                    case "DEFAULT":
                        break;
                    case "ADMIN":
                        out.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                        break;
                    case "SUPERADMIN":
                        out.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));
                        break;
                    default:
                        out.add(new SimpleGrantedAuthority(upper.startsWith("ROLE_") ? upper : "ROLE_" + upper));
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

    // ===== Small utils =====
    private static String rid() { return UUID.randomUUID().toString().substring(0, 8); }
    private boolean hasText(String s) { return s != null && !s.trim().isEmpty(); }
    private String coalesce(String... vals) {
        if (vals == null) return null;
        for (String v : vals) if (hasText(v)) return v;
        return null;
    }
}
