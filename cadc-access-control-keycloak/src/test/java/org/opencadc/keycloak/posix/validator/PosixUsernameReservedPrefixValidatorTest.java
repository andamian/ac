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

package org.opencadc.keycloak.posix.validator;

import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationError;
import org.keycloak.validate.ValidatorConfig;
import org.opencadc.keycloak.posix.PosixConfig;
import org.opencadc.keycloak.posix.PosixRuntimeConfig;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PosixUsernameReservedPrefixValidatorTest {

    private PosixConfig previousConfig;

    @Before
    public void setUp() {
        previousConfig = PosixRuntimeConfig.get();
    }

    @After
    public void tearDown() {
        PosixRuntimeConfig.set(previousConfig);
    }

    @Test
    public void testRejectsReservedPrefixUsernameWhenConfigured() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, "https://ska-iam.stfc.ac.uk/:ska");
        PosixRuntimeConfig.set(PosixConfig.fromMap(values));

        ValidationContext context = new ValidationContext();
        PosixUsernameReservedPrefixValidator.INSTANCE.validate("ska-user", "username", context,
                ValidatorConfig.EMPTY);

        assertTrue(hasError(context, PosixUsernameReservedPrefixValidator.MESSAGE_POSIX_USERNAME_RESERVED_PREFIX));
    }

    @Test
    public void testAllowsReservedPrefixUsernameWhenNoPrefixesConfigured() {
        PosixRuntimeConfig.set(PosixConfig.fromMap(null));

        ValidationContext context = new ValidationContext();
        PosixUsernameReservedPrefixValidator.INSTANCE.validate("ska-user", "username", context,
                ValidatorConfig.EMPTY);

        assertFalse(hasError(context, PosixUsernameReservedPrefixValidator.MESSAGE_POSIX_USERNAME_RESERVED_PREFIX));
    }

    @Test
    public void testAllowsNonReservedUsername() {
        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, "https://ska-iam.stfc.ac.uk/:ska");
        PosixRuntimeConfig.set(PosixConfig.fromMap(values));

        ValidationContext context = new ValidationContext();
        PosixUsernameReservedPrefixValidator.INSTANCE.validate("jsmith", "username", context,
                ValidatorConfig.EMPTY);

        assertFalse(hasError(context, PosixUsernameReservedPrefixValidator.MESSAGE_POSIX_USERNAME_RESERVED_PREFIX));
    }

    private boolean hasError(ValidationContext context, String message) {
        for (ValidationError error : context.getErrors()) {
            if (message.equals(error.getMessage())) {
                return true;
            }
        }
        return false;
    }
}
