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

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class PosixIssPrefixConfigResolverTest {

    @Test
    public void testApplyIssuerPrefixesUpdatesRuntimeConfig() {
        PosixRuntimeConfig.set(PosixConfig.fromMap(null));
        PosixConfigBootstrap.applyIssuerPrefixes("https://ska-iam.stfc.ac.uk/:ska");
        assertEquals("ska", PosixRuntimeConfig.get().getIssuerUsernamePrefix("https://ska-iam.stfc.ac.uk/").get());
    }
}
