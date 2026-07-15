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

import org.keycloak.userprofile.DeclarativeUserProfileProviderFactory;
import org.keycloak.userprofile.UserProfileMetadata;

/**
 * Extends the declarative user profile provider to enforce POSIX username rules
 * on admin user creation and other local username entry flows.
 */
public class PosixUserProfileProviderFactory extends DeclarativeUserProfileProviderFactory {

    private static final int PROVIDER_PRIORITY = 100;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return PROVIDER_PRIORITY;
    }

    @Override
    protected UserProfileMetadata configureUserProfile(UserProfileMetadata metadata) {
        UserProfileMetadata configured = super.configureUserProfile(metadata);
        PosixUserProfileSupport.addUsernameValidators(configured);
        return configured;
    }
}
