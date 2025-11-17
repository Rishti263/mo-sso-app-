package com.ssoapp.controller;

import com.ssoapp.entity.User;
import com.ssoapp.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

@Controller
@RequestMapping("/sso/saml")
@RequiredArgsConstructor
public class SAMLSSOController {

    private static final Logger log = LoggerFactory.getLogger(SAMLSSOController.class);
    private final UserService userService;

    // ===== Hardcoded IdP values (from miniOrange) =====
    private static final String IDP_SSO_URL   = "https://rishti.xecurify.com/moas/idp/samlsso/d991d479-878b-457b-9da7-fa5630ca61de";
    private static final String IDP_ENTITY_ID = "https://login.xecurify.com/moas/379424/d991d479-878b-457b-9da7-fa5630ca61de";

    // ===== Your SP identifiers (must match miniOrange app config) =====
    private static final String SP_ENTITY_ID = "http://localhost:8080/sso/saml/metadata";  // Audience/Issuer for SP
    private static final String ACS_URL      = "http://localhost:8080/sso/saml/callback";  // ACS endpoint (HTTP-POST)

    // ===== Start SAML login (Redirect binding) =====
    @GetMapping("/login")
    public String startLogin(HttpSession session) {
        // Build deflated, Base64, URL-encoded AuthnRequest
        String samlRequest = buildRedirectBindingRequest();
        String relayState = UUID.randomUUID().toString();
        session.setAttribute("saml_relay_state", relayState);

        String redirect = IDP_SSO_URL
                + (IDP_SSO_URL.contains("?") ? "&" : "?")
                + "SAMLRequest=" + samlRequest
                + "&RelayState=" + urlEncode(relayState);

        log.info("Redirecting to IdP SSO URL: {}", IDP_SSO_URL);
        return "redirect:" + redirect;
    }

    // ===== ACS accepts POST (primary) and GET (for local tests) =====
    @PostMapping("/callback")
    public void acsPost(@RequestParam(required = false) String SAMLResponse,
                        @RequestParam(required = false) String RelayState,
                        HttpServletRequest req,
                        HttpServletResponse res) throws Exception {
        handleAcs(SAMLResponse, RelayState, req, res);
    }

    @GetMapping("/callback")
    public void acsGet(@RequestParam(required = false) String SAMLResponse,
                       @RequestParam(required = false) String RelayState,
                       HttpServletRequest req,
                       HttpServletResponse res) throws Exception {
        handleAcs(SAMLResponse, RelayState, req, res);
    }

    private void handleAcs(String samlResponseB64, String relayState,
                           HttpServletRequest req, HttpServletResponse res) throws Exception {
        HttpSession session = req.getSession();

        if (isBlank(samlResponseB64)) {
            res.sendRedirect("/login?error=saml_no_response");
            return;
        }

        String expected = (String) session.getAttribute("saml_relay_state");
        if (expected != null && !expected.equals(relayState)) {
            log.warn("RelayState mismatch. expected={}, got={}", expected, relayState);
        }

        Map<String,Object> attrs = parseSAMLResponse(samlResponseB64);
        if (attrs == null || attrs.isEmpty()) {
            res.sendRedirect("/login?error=saml_parse_failed");
            return;
        }

        // (Optional) Soft check for IdP Issuer in the assertion (no signature verification here)
        String issuer = (String) attrs.get("_issuer");
        if (!isBlank(issuer) && !IDP_ENTITY_ID.equals(issuer)) {
            log.warn("Assertion Issuer != expected IdP entityId. got={}, expected={}", issuer, IDP_ENTITY_ID);
        }

        User user = upsertUserFromAttributes(attrs);
        authenticate(user, req, res);
        session.removeAttribute("saml_relay_state");
        res.sendRedirect(routeByRole(user.getRole()));
    }

    // ===== Metadata (SP entityID + ACS must match miniOrange) =====
    @GetMapping("/metadata")
    @ResponseBody
    public String metadata() {
        return String.format(
                "<?xml version=\"1.0\"?>\n" +
                        "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\">\n" +
                        "  <SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
                        "    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>\n" +
                        "    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"%s\" index=\"0\"/>\n" +
                        "  </SPSSODescriptor>\n" +
                        "</EntityDescriptor>\n",
                SP_ENTITY_ID, ACS_URL
        );
    }

    @GetMapping("/sp-info")
    @ResponseBody
    public Map<String,String> spInfo() {
        Map<String,String> m = new HashMap<>();
        m.put("spEntityId", SP_ENTITY_ID);
        m.put("acsUrl", ACS_URL);
        m.put("metadataUrl", "http://localhost:8080/sso/saml/metadata");
        m.put("idpSsoUrl", IDP_SSO_URL);
        m.put("idpEntityId", IDP_ENTITY_ID);
        return m;
    }

    // ===== Build Redirect-binding AuthnRequest (DEFLATE + Base64 + URL-encode) =====
    private String buildRedirectBindingRequest() {
        String xml =
                "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
                        "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
                        "ID=\"_" + UUID.randomUUID() + "\" Version=\"2.0\" IssueInstant=\"" + Instant.now() + "\" " +
                        "Destination=\"" + IDP_SSO_URL + "\" " +
                        "AssertionConsumerServiceURL=\"" + ACS_URL + "\" " +
                        "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">" +
                        "<saml:Issuer>" + SP_ENTITY_ID + "</saml:Issuer>" +
                        "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" AllowCreate=\"true\"/>" +
                        "</samlp:AuthnRequest>";

        return deflateBase64Url(xml);
    }

    private static String deflateBase64Url(String xml) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
                dos.write(xml.getBytes(StandardCharsets.UTF_8));
            }
            String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
            return urlEncode(b64);
        } catch (Exception e) {
            throw new RuntimeException("SAMLRequest encode failed", e);
        }
    }

    private static String urlEncode(String s) {
        try { return URLEncoder.encode(s, StandardCharsets.UTF_8.name()); }
        catch (Exception e) { return s; }
    }
    private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

    // ===== Parse SAMLResponse (Base64 → XML → attributes) =====
    private Map<String,Object> parseSAMLResponse(String samlResponseB64) {
        try {
            byte[] xmlBytes = Base64.getDecoder().decode(samlResponseB64);
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            DocumentBuilder b = f.newDocumentBuilder();
            Document doc = b.parse(new ByteArrayInputStream(xmlBytes));

            Map<String,Object> out = new HashMap<>();

            // Issuer (IdP entityID)
            NodeList issuers = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer");
            if (issuers.getLength() > 0) {
                out.put("_issuer", issuers.item(0).getTextContent());
            }

            // Subject NameID
            NodeList nameId = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","NameID");
            if (nameId.getLength() > 0) out.put("username", nameId.item(0).getTextContent());

            // Attributes
            NodeList attrs = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Attribute");
            for (int i=0;i<attrs.getLength();i++) {
                Element e = (Element) attrs.item(i);
                String key = e.getAttribute("Name");
                NodeList vals = e.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","AttributeValue");
                if (vals.getLength() > 0) out.put(key, vals.item(0).getTextContent());
            }

            // Common mappings (miniOrange)
            if (!out.containsKey("email") && out.containsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
                out.put("email", out.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"));
            if (!out.containsKey("username") && out.containsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"))
                out.put("username", out.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"));
            if (!out.containsKey("role") && out.containsKey("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"))
                out.put("role", out.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));

            return out;
        } catch (Exception e) {
            log.error("SAMLResponse parse error", e);
            return null;
        }
    }

    // ===== User + SecurityContext =====
    private User upsertUserFromAttributes(Map<String,Object> attrs) {
        String username = pick(attrs, "username", "NameID", "email");
        String email = pick(attrs, "email", "mail", "emailAddress");
        if (isBlank(username)) username = !isBlank(email) ? email.split("@")[0] : "saml_user";

        String role = "ENDUSER";
        Object rolesObj = attrs.get("role");
        if (rolesObj == null) rolesObj = attrs.get("roles");
        if (rolesObj == null) rolesObj = attrs.get("groups");
        List<String> roles = normalizeRoles(rolesObj);
        if (roles.contains("SUPERADMIN")) role = "SUPERADMIN";
        else if (roles.contains("ADMIN")) role = "ADMIN";

        Optional<User> existing = userService.findByUsername(username);
        if (existing.isPresent()) return existing.get();

        User u = new User();
        u.setUsername(username);
        u.setEmail(!isBlank(email) ? email : (username + "@saml.local"));
        u.setPassword("");
        u.setRole(role);
        u.setCreatedBy("SAML_SSO");
        return userService.registerUser(u);
    }

    private void authenticate(User user, HttpServletRequest req, HttpServletResponse res) {
        HttpSession session = req.getSession(true);
        String springRole = "ROLE_" + user.getRole().toUpperCase(Locale.ROOT);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(), null, Collections.singletonList(new SimpleGrantedAuthority(springRole)));

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        new HttpSessionSecurityContextRepository().saveContext(ctx, req, res);
        session.setAttribute("user", user);
    }

    private static String pick(Map<String,Object> m, String... keys) {
        for (String k : keys) {
            Object v = m.get(k);
            if (v != null) {
                String s = v.toString().trim();
                if (!s.isEmpty()) return s;
            }
        }
        return null;
    }

    private static List<String> normalizeRoles(Object rolesObj) {
        List<String> out = new ArrayList<>();
        if (rolesObj instanceof String) {
            String s = ((String) rolesObj).trim();
            if (!s.isEmpty()) {
                for (String p : s.split("[,;|]")) {
                    String r = p.trim().toUpperCase(Locale.ROOT);
                    if (!r.isEmpty()) out.add(r);
                }
            }
        } else if (rolesObj instanceof Collection<?>) {
            for (Object o : (Collection<?>) rolesObj) {
                if (o != null) {
                    String r = o.toString().trim().toUpperCase(Locale.ROOT);
                    if (!r.isEmpty()) out.add(r);
                }
            }
        }
        if (out.isEmpty()) out.add("ENDUSER");
        return out;
    }

    private static String routeByRole(String role) {
        String r = role == null ? "" : role.toUpperCase(Locale.ROOT);
        if ("SUPERADMIN".equals(r)) return "/superadmin/dashboard";
        if ("ADMIN".equals(r))      return "/admin/dashboard";
        return "/user/dashboard";
    }
}
