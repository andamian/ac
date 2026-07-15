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
import static org.junit.Assert.fail;

public class PosixUsernameValidationTest {

    @Test
    public void testRejectsInvalidUsername() {
        try {
            PosixUsernameValidation.requireValidUsername("j.smith@example.com");
            fail("Expected PosixAllocationException");
        } catch (PosixAllocationException e) {
            assertEquals("Invalid POSIX username: j.smith@example.com", e.getMessage());
        }
    }

    @Test
    public void testAcceptsValidUsername() {
        PosixUsernameValidation.requireValidUsername("test_admin_user");
    }
}
