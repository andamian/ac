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

/**
 * Holds POSIX listener configuration for components that run outside the event listener factory.
 */
public final class PosixRuntimeConfig {

    private static volatile PosixConfig config = PosixConfig.fromMap(null);

    private PosixRuntimeConfig() {
    }

    public static void set(PosixConfig posixConfig) {
        config = posixConfig == null ? PosixConfig.fromMap(null) : posixConfig;
    }

    public static void mergeIssuerPrefixes(Map<String, String> issuerPrefixes) {
        if (issuerPrefixes == null || issuerPrefixes.isEmpty()) {
            return;
        }
        config = config.withIssuerUsernamePrefixes(issuerPrefixes);
    }

    public static PosixConfig get() {
        return config;
    }
}
