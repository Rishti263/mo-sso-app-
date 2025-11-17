package com.ssoapp.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "sso_config")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SSOConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "sso_type")
    private String ssoType; // JWT, SAML, OAUTH

    @Column(name = "idp_url", length = 1000)
    private String idpUrl;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "entity_id")
    private String entityId;

    @Column(name = "sso_url", length = 1000)
    private String ssoUrl;

    @Column(name = "certificate", length = 5000)
    private String certificate;

    @Column(name = "is_enabled")
    private Boolean isEnabled = false;
}