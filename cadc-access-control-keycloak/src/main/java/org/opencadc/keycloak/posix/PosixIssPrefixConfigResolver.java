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

import org.keycloak.Config;
import org.opencadc.keycloak.posix.events.PosixEventListenerProviderFactory;

/**
 * Resolves iss-prefix configuration from Keycloak SPI scopes and {@code keycloak.conf}.
 * <p>
 * Keycloak maps SPI property names with dots to dashes in config files. For example,
 * {@code config.get("posix.username.iss-prefixes")} reads
 * {@code spi-events-listener--opencadc-posix--posix-username-iss-prefixes} from
 * {@code keycloak.conf}, not {@code posix.username.iss-prefixes}.
 */
public final class PosixIssPrefixConfigResolver {

    /** Recommended {@code keycloak.conf} key (double-dash SPI format). */
    public static final String KEYCLOAK_CONF_ISS_PREFIXES =
            "spi-events-listener--opencadc-posix--posix-username-iss-prefixes";

    /** Legacy single-dash {@code keycloak.conf} key. */
    public static final String KEYCLOAK_CONF_ISS_PREFIXES_LEGACY =
            "spi-events-listener-opencadc-posix-posix-username-iss-prefixes";

    private static final String EVENT_LISTENER_SPI = "eventsListener";

    private PosixIssPrefixConfigResolver() {
    }

    public static String resolve(Config.Scope scope) {
        if (scope != null) {
            String fromScope = trimToNull(scope.get(PosixConfig.ISS_PREFIXES));
            if (fromScope != null) {
                return fromScope;
            }
        }

        Config.Scope listenerScope = Config.scope(EVENT_LISTENER_SPI, PosixEventListenerProviderFactory.PROVIDER_ID);
        if (listenerScope != null) {
            String fromGlobalScope = trimToNull(listenerScope.get(PosixConfig.ISS_PREFIXES));
            if (fromGlobalScope != null) {
                return fromGlobalScope;
            }
        }

        String fromKeycloakConf = resolveFromKeycloakConf(scope, listenerScope);
        if (fromKeycloakConf != null) {
            return fromKeycloakConf;
        }

        return null;
    }

    private static String resolveFromKeycloakConf(Config.Scope scope, Config.Scope listenerScope) {
        Config.Scope root = scope != null ? scope.root() : listenerScope != null ? listenerScope.root() : null;
        if (root == null) {
            return null;
        }
        for (String confKey : new String[] {KEYCLOAK_CONF_ISS_PREFIXES, KEYCLOAK_CONF_ISS_PREFIXES_LEGACY}) {
            String value = trimToNull(root.get(confKey));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
