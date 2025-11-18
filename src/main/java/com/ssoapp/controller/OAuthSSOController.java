package com.ssoapp.controller;

import com.ssoapp.entity.SSOConfig;
import com.ssoapp.entity.User;
import com.ssoapp.service.SSOConfigService;
import com.ssoapp.service.UserService;
import io.jsonwebtoken.*;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.Base64;

@Controller
@RequestMapping("/sso/oauth")
@RequiredArgsConstructor
@Slf4j
public class OAuthSSOController {

    private final RestTemplate rest = new RestTemplate();
    private final SSOConfigService ssoConfigService;
    private final UserService userService;

    /**
     * Dynamically build callback URL based on current request
     */
    private String buildCallbackUrl(HttpServletRequest request) {
        String scheme = request.getHeader("X-Forwarded-Proto");
        if (scheme == null || scheme.isEmpty()) {
            scheme = request.getScheme();
        }

        String host = request.getHeader("Host");
        if (host == null || host.isEmpty()) {
            host = request.getServerName();
            int port = request.getServerPort();
            if ((scheme.equals("http") && port != 80) || (scheme.equals("https") && port != 443)) {
                host = host + ":" + port;
            }
        }

        String callbackUrl = scheme + "://" + host + "/sso/oauth/callback";
        log.info("Dynamic OAuth callback URL: {}", callbackUrl);
        return callbackUrl;
    }

    @GetMapping("/login")
    public String initiateOAuthLogin(HttpSession session, HttpServletRequest request) {
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

        String callbackUrl = buildCallbackUrl(request);

        try {
            String authUrl =
                    cfg.getIdpUrl()
                            + "?response_type=code"
                            + "&client_id=" + URLEncoder.encode(cfg.getClientId(), StandardCharsets.UTF_8.name())
                            + "&redirect_uri=" + URLEncoder.encode(callbackUrl, StandardCharsets.UTF_8.name())
                            + "&scope=" + URLEncoder.encode("openid profile email", StandardCharsets.UTF_8.name())
                            + "&state=" + state;

            log.info("[{}] Redirecting to OAuth Authorization: {}", rid, authUrl);
            log.info("[{}] Using callback URL: {}", rid, callbackUrl);
            return "redirect:" + authUrl;
        } catch (Exception e) {
            log.error("[{}] OAuth auth URL build failed", rid, e);
            return "redirect:/login?error=oauth_init_failed";
        }
    }

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

            String callbackUrl = buildCallbackUrl(req);
            log.info("[{}] Using callback URL for token exchange: {}", rid, callbackUrl);

            // Exchange code -> tokens
            Map<String, Object> tokenResponse = exchangeCodeForToken(code, cfg, callbackUrl);
            if (tokenResponse == null) {
                log.warn("[{}] Token exchange returned null", rid);
                res.sendRedirect("/login?error=oauth_token_null");
                return;
            }
            log.info("[{}] Token response keys: {}", rid, tokenResponse.keySet());

            // Get id_token
            Object idt = tokenResponse.get("id_token");
            if (!(idt instanceof String) || !hasText((String) idt)) {
                log.warn("[{}] Missing id_token in token response", rid);
                res.sendRedirect("/login?error=oauth_no_id_token");
                return;
            }
            String idToken = (String) idt;
            log.info("[{}] id_token received, length: {}", rid, idToken.length());

            // Parse without verification first to see the header
            Claims claims = parseIdTokenWithoutVerification(idToken);
            log.info("[{}] id_token claims (unverified): sub={}, iss={}, aud={}", 
                rid, claims.getSubject(), claims.getIssuer(), claims.get("aud"));

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
                u.setPassword("");
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

    @SuppressWarnings("unchecked")
    private Map<String, Object> exchangeCodeForToken(String code, SSOConfig cfg, String callbackUrl) {
        final String rid = rid();
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "authorization_code");
            form.add("code", code);
            form.add("redirect_uri", callbackUrl);
            form.add("client_id", cfg.getClientId());
            form.add("client_secret", cfg.getClientSecret());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setBasicAuth(cfg.getClientId(), cfg.getClientSecret());

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
            log.info("[{}] Token POST → {} with callback: {}", rid, cfg.getSsoUrl(), callbackUrl);

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

    /**
     * Parse JWT without signature verification to extract claims
     * miniOrange likely uses RS256, so we can't verify with client_secret
     * For production, you should verify using JWK endpoint or public key
     */
    private Claims parseIdTokenWithoutVerification(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) throw new MalformedJwtException("Invalid JWT structure");
            
            // Decode payload (second part)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            log.info("JWT payload: {}", payload);
            
            // Parse using Jwts parser without signature verification
            int lastDot = token.lastIndexOf('.');
            String unsignedToken = token.substring(0, lastDot + 1);
            
            return Jwts.parserBuilder()
                    .setAllowedClockSkewSeconds(300) // 5 minutes
                    .build()
                    .parseClaimsJwt(unsignedToken)
                    .getBody();
        } catch (Exception e) {
            log.error("Failed to parse id_token without verification", e);
            throw new JwtException("Failed to parse id_token", e);
        }
    }

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

    private static String rid() { return UUID.randomUUID().toString().substring(0, 8); }
    private boolean hasText(String s) { return s != null && !s.trim().isEmpty(); }
    private String coalesce(String... vals) {
        if (vals == null) return null;
        for (String v : vals) if (hasText(v)) return v;
        return null;
    }
}
