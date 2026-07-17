/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2026.                            (c) 2026.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 ************************************************************************
 */

package org.opencadc.keycloak.posix;

import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Applies optional OIDC issuer-based POSIX username prefixes for broker-provisioned accounts.
 */
public final class PosixBrokerUsernamePrefix {

    private static final Logger LOG = Logger.getLogger(PosixBrokerUsernamePrefix.class);

    private PosixBrokerUsernamePrefix() {
    }

    public static boolean hasBrokerLink(KeycloakSession session, RealmModel realm, UserModel user) {
        return session.users().getFederatedIdentitiesStream(realm, user).findAny().isPresent();
    }

    public static Optional<String> resolvePrefixForUser(KeycloakSession session, RealmModel realm, UserModel user,
            PosixConfig config) {
        return session.users().getFederatedIdentitiesStream(realm, user)
                .map(federated -> resolveConfiguredPrefix(realm, federated, config))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();
    }

    public static Optional<String> resolveConfiguredPrefix(RealmModel realm, FederatedIdentityModel federated,
            PosixConfig config) {
        if (federated == null) {
            return Optional.empty();
        }
        IdentityProviderModel idp = realm.getIdentityProviderByAlias(federated.getIdentityProvider());
        return resolveConfiguredPrefix(idp, config);
    }

    public static Optional<String> resolveConfiguredPrefix(IdentityProviderModel idp, PosixConfig config) {
        if (idp == null || config == null) {
            return Optional.empty();
        }
        String issuer = idp.getConfig().get(IdentityProviderModel.ISSUER);
        if (issuer == null || issuer.trim().isEmpty()) {
            return Optional.empty();
        }
        Optional<String> prefix = config.getIssuerUsernamePrefix(issuer);
        if (prefix.isEmpty()) {
            LOG.debugf("No POSIX username prefix configured for issuer %s (IdP alias %s)",
                    PosixConfig.normalizeIssuer(issuer), idp.getAlias());
        }
        return prefix;
    }

    public static void applyIfConfigured(KeycloakSession session, RealmModel realm, UserModel user, PosixConfig config,
            boolean adminCreated) {
        if (adminCreated || !hasBrokerLink(session, realm, user)) {
            return;
        }

        Optional<String> prefix = resolvePrefixForUser(session, realm, user, config);
        if (prefix.isEmpty()) {
            return;
        }

        String base = user.getFirstAttribute(PosixAttributeNames.USERNAME);
        if (!PosixConfig.isPosixUsernameCandidate(base)) {
            base = PosixConfig.isPosixUsernameCandidate(user.getUsername()) ? user.getUsername().trim() : null;
        }
        if (base == null) {
            LOG.warnf("Skipping POSIX username prefix for broker user %s: no valid base username",
                    user.getUsername());
            return;
        }

        applyPrefixedUsername(session, realm, user, PosixConfig.applyIdpUsernamePrefix(prefix.get(), base));
    }

    static void applyPrefixedUsername(KeycloakSession session, RealmModel realm, UserModel user, String prefixed) {
        UserModel existing = session.users().getUserByUsername(realm, prefixed);
        if (existing != null && !existing.getId().equals(user.getId())) {
            throw new PosixAllocationException("Prefixed username already in use: " + prefixed);
        }
        if (PosixUsernameInUseChecks.isPosixUsernameInUse(session, realm, prefixed, user.getId())) {
            throw new PosixAllocationException("POSIX username already in use: " + prefixed);
        }
        user.setUsername(prefixed);
        user.setSingleAttribute(PosixAttributeNames.USERNAME, prefixed);
    }
}
