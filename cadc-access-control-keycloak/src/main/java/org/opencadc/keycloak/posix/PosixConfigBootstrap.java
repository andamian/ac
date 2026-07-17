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

import java.util.Map;
import org.keycloak.Config;

/**
 * Loads shared POSIX configuration used by multiple SPI factories.
 */
public final class PosixConfigBootstrap {

    private PosixConfigBootstrap() {
    }

    public static void loadIssuerPrefixes(Config.Scope scope) {
        applyIssuerPrefixes(PosixIssPrefixConfigResolver.resolve(scope));
    }

    static void applyIssuerPrefixes(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return;
        }
        Map<String, String> issuerPrefixes = PosixConfig.parseIssuerPrefixes(raw);
        if (!issuerPrefixes.isEmpty()) {
            PosixRuntimeConfig.mergeIssuerPrefixes(issuerPrefixes);
        }
    }
}
