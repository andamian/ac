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

import java.util.Collections;
import java.util.List;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.validate.AbstractStringValidator;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationError;
import org.keycloak.validate.ValidatorConfig;
import org.opencadc.keycloak.posix.PosixRuntimeConfig;

/**
 * Rejects local usernames reserved for external IdP POSIX account creation.
 */
public class PosixUsernameReservedPrefixValidator extends AbstractStringValidator implements ConfiguredProvider {

    public static final String ID = "opencadc-posix-username-reserved-prefix";

    public static final String MESSAGE_POSIX_USERNAME_RESERVED_PREFIX = "posix-username-reserved-prefix";

    public static final PosixUsernameReservedPrefixValidator INSTANCE = new PosixUsernameReservedPrefixValidator();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Rejects usernames reserved for external identity provider POSIX account creation.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    protected void doValidate(String value, String inputHint, ValidationContext context, ValidatorConfig config) {
        if (value == null || value.trim().isEmpty()) {
            return;
        }
        if (PosixRuntimeConfig.get().isReservedPrefixUsername(value)) {
            context.addError(new ValidationError(ID, inputHint, MESSAGE_POSIX_USERNAME_RESERVED_PREFIX, value));
        }
    }
}
