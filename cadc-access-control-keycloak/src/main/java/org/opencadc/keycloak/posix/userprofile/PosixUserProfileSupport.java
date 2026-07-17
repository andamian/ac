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

package org.opencadc.keycloak.posix.userprofile;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import org.keycloak.models.UserModel;
import org.keycloak.userprofile.AttributeMetadata;
import org.keycloak.userprofile.AttributeValidatorMetadata;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileMetadata;
import org.opencadc.keycloak.posix.validator.PosixUsernameFormatValidator;
import org.opencadc.keycloak.posix.validator.PosixUsernameReservedPrefixValidator;
import org.opencadc.keycloak.posix.validator.PosixUsernameUniqueValidator;

/**
 * Adds POSIX username validators to Keycloak user profile metadata.
 *
 * <p>Validators are intentionally limited to contexts used when a username is
 * first chosen (admin create, registration, SCIM). They must not be attached to
 * {@link UserProfileContext#UPDATE_PROFILE} because Keycloak's Verify Profile
 * required action validates existing users in that context on every login.
 */
public final class PosixUserProfileSupport {

    private static final Set<UserProfileContext> USERNAME_VALIDATION_CONTEXTS = EnumSet.of(
            UserProfileContext.USER_API,
            UserProfileContext.REGISTRATION,
            UserProfileContext.SCIM);

    private PosixUserProfileSupport() {
    }

    public static void addUsernameValidators(UserProfileMetadata metadata) {
        if (metadata == null || !USERNAME_VALIDATION_CONTEXTS.contains(metadata.getContext())) {
            return;
        }
        List<AttributeMetadata> usernameAttributes = metadata.getAttribute(UserModel.USERNAME);
        if (usernameAttributes == null || usernameAttributes.isEmpty()) {
            return;
        }
        AttributeMetadata username = usernameAttributes.get(0);
        username.addValidators(List.of(
                new AttributeValidatorMetadata(PosixUsernameFormatValidator.ID),
                new AttributeValidatorMetadata(PosixUsernameUniqueValidator.ID),
                new AttributeValidatorMetadata(PosixUsernameReservedPrefixValidator.ID)));
    }
}
