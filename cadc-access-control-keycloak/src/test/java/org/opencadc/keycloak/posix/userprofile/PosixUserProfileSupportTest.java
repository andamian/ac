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

import java.util.List;
import org.junit.Test;
import org.keycloak.models.UserModel;
import org.keycloak.userprofile.AttributeMetadata;
import org.keycloak.userprofile.AttributeValidatorMetadata;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileMetadata;
import org.opencadc.keycloak.posix.validator.PosixUsernameFormatValidator;
import org.opencadc.keycloak.posix.validator.PosixUsernameUniqueValidator;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PosixUserProfileSupportTest {

    @Test
    public void testAddsValidatorsForAdminUserApiContext() {
        UserProfileMetadata metadata = new UserProfileMetadata(UserProfileContext.USER_API);
        metadata.addAttribute(UserModel.USERNAME, -2);

        PosixUserProfileSupport.addUsernameValidators(metadata);

        List<AttributeValidatorMetadata> validators = metadata.getAttribute(UserModel.USERNAME).get(0).getValidators();
        assertTrue(containsValidator(validators, PosixUsernameFormatValidator.ID));
        assertTrue(containsValidator(validators, PosixUsernameUniqueValidator.ID));
    }

    @Test
    public void testSkipsUpdateProfileContextUsedByVerifyProfileOnLogin() {
        UserProfileMetadata metadata = new UserProfileMetadata(UserProfileContext.UPDATE_PROFILE);
        metadata.addAttribute(UserModel.USERNAME, -2);

        PosixUserProfileSupport.addUsernameValidators(metadata);

        List<AttributeValidatorMetadata> validators = metadata.getAttribute(UserModel.USERNAME).get(0).getValidators();
        assertFalse(containsValidator(validators, PosixUsernameFormatValidator.ID));
        assertFalse(containsValidator(validators, PosixUsernameUniqueValidator.ID));
    }

    @Test
    public void testSkipsIdpReviewContext() {
        UserProfileMetadata metadata = new UserProfileMetadata(UserProfileContext.IDP_REVIEW);
        metadata.addAttribute(UserModel.USERNAME, -2);

        PosixUserProfileSupport.addUsernameValidators(metadata);

        List<AttributeValidatorMetadata> validators = metadata.getAttribute(UserModel.USERNAME).get(0).getValidators();
        assertFalse(containsValidator(validators, PosixUsernameFormatValidator.ID));
        assertFalse(containsValidator(validators, PosixUsernameUniqueValidator.ID));
    }

    private boolean containsValidator(List<AttributeValidatorMetadata> validators, String id) {
        for (AttributeValidatorMetadata validator : validators) {
            if (id.equals(validator.getValidatorId())) {
                return true;
            }
        }
        return false;
    }
}
