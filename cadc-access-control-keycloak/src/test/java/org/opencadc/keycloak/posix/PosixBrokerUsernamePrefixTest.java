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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.Test;
import org.keycloak.models.IdentityProviderModel;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PosixBrokerUsernamePrefixTest {

    @Test
    public void testResolveConfiguredPrefixMatchesNormalizedIssuer() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, "https://ska-iam.stfc.ac.uk/:ska");
        PosixConfig config = PosixConfig.fromMap(values);

        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("SKAIAM");
        idp.getConfig().put(IdentityProviderModel.ISSUER, "https://ska-iam.stfc.ac.uk");

        Optional<String> prefix = PosixBrokerUsernamePrefix.resolveConfiguredPrefix(idp, config);
        assertEquals("ska", prefix.get());
    }

    @Test
    public void testResolveConfiguredPrefixReturnsEmptyWhenIssuerUnconfigured() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, "https://ska-iam.stfc.ac.uk/:ska");
        PosixConfig config = PosixConfig.fromMap(values);

        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("OTHER");
        idp.getConfig().put(IdentityProviderModel.ISSUER, "https://other.example/");

        assertFalse(PosixBrokerUsernamePrefix.resolveConfiguredPrefix(idp, config).isPresent());
    }

    @Test
    public void testDifferentIssuersCanUseSamePreferredUsernameBase() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES,
                "https://ska-iam.stfc.ac.uk/:ska,https://iam.indigo.example/:indigo");
        PosixConfig config = PosixConfig.fromMap(values);

        assertEquals("ska-user", PosixConfig.applyIdpUsernamePrefix(
                config.getIssuerUsernamePrefix("https://ska-iam.stfc.ac.uk/").get(), "user"));
        assertEquals("indigo-user", PosixConfig.applyIdpUsernamePrefix(
                config.getIssuerUsernamePrefix("https://iam.indigo.example/").get(), "user"));
    }
}
