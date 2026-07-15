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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Validates that a Keycloak username is acceptable as {@code posix.username}.
 */
public final class PosixUsernameValidation {

    private PosixUsernameValidation() {
    }

    public static void requireValidKeycloakUsername(UserModel user) {
        if (user == null) {
            throw new PosixAllocationException("Cannot provision POSIX account: user not found");
        }
        requireValidUsername(user.getUsername());
    }

    public static void requireValidUsername(String username) {
        if (!PosixUsernameRules.isValid(username)) {
            throw new PosixAllocationException("Invalid POSIX username: " + username);
        }
    }

    public static void requireAvailablePosixUsername(KeycloakSession session, RealmModel realm, UserModel user) {
        String username = user.getUsername();
        if (PosixUsernameInUseChecks.isPosixUsernameInUse(session, realm, username, user.getId())) {
            throw new PosixAllocationException("POSIX username already in use: " + username);
        }
    }

    public static void requireValidAndAvailableKeycloakUsername(KeycloakSession session, RealmModel realm,
            UserModel user) {
        requireValidKeycloakUsername(user);
        requireAvailablePosixUsername(session, realm, user);
    }
}
