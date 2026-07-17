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
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PosixRuntimeConfigTest {

    @After
    public void tearDown() {
        PosixRuntimeConfig.set(PosixConfig.fromMap(null));
    }

    @Test
    public void testMergeIssuerPrefixesUpdatesReservedUsernameCheck() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, "https://ska-iam.stfc.ac.uk/:ska");
        PosixRuntimeConfig.set(PosixConfig.fromMap(null));
        PosixRuntimeConfig.mergeIssuerPrefixes(PosixConfig.parseIssuerPrefixes(
                values.get(PosixConfig.ISS_PREFIXES)));

        assertEquals(1, PosixRuntimeConfig.get().getReservedUsernamePrefixes().size());
        assertTrue(PosixRuntimeConfig.get().isReservedPrefixUsername("ska-user"));
    }
}
