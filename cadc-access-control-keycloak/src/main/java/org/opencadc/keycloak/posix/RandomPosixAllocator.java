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
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 ************************************************************************
 */

package org.opencadc.keycloak.posix;

import java.util.Collections;
import java.util.Random;
import java.util.Set;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Allocates POSIX UIDs using a pseudo-random strategy with collision checks.
 */
public final class RandomPosixAllocator {

    private final PosixConfig config;
    private final Random random;
    private final Set<Integer> uidsInUseForTesting;

    public RandomPosixAllocator(PosixConfig config) {
        this(config, new Random(), null);
    }

    static RandomPosixAllocator forTesting(PosixConfig config, Random random, Set<Integer> uidsInUse) {
        return new RandomPosixAllocator(config, random, uidsInUse);
    }

    private RandomPosixAllocator(PosixConfig config, Random random, Set<Integer> uidsInUseForTesting) {
        if (config == null) {
            throw new IllegalArgumentException("config is null");
        }
        if (random == null) {
            throw new IllegalArgumentException("random is null");
        }
        this.config = config;
        this.random = random;
        this.uidsInUseForTesting = uidsInUseForTesting == null
                ? null
                : Collections.unmodifiableSet(uidsInUseForTesting);
    }

    static PosixDetails allocateForTesting(RandomPosixAllocator allocator, String keycloakUsername,
            String presetPosixUsername) {
        if (allocator.uidsInUseForTesting == null) {
            throw new IllegalArgumentException("allocator is not configured for testing");
        }
        return allocator.allocateForTesting(keycloakUsername, presetPosixUsername);
    }

    private PosixDetails allocateForTesting(String keycloakUsername, String presetPosixUsername) {
        if (keycloakUsername == null) {
            throw new IllegalArgumentException("keycloakUsername is null");
        }
        int range = config.getUidMax() - config.getUidMin();
        if (range <= 0) {
            throw new PosixAllocationException("invalid UID range: " + config.getUidMin()
                    + ".." + config.getUidMax());
        }

        for (int attempt = 0; attempt < config.getMaxRetries(); attempt++) {
            int uid = config.getUidMin() + random.nextInt(range);
            if (!uidsInUseForTesting.contains(uid)) {
                return buildDetails(keycloakUsername, presetPosixUsername, uid);
            }
        }

        throw new PosixAllocationException("failed to allocate UID for user " + keycloakUsername
                + " after " + config.getMaxRetries() + " attempts");
    }

    public PosixDetails allocateInKeycloakDb(UserModel user, KeycloakSession session, RealmModel realm) {
        if (user == null) {
            throw new IllegalArgumentException("user is null");
        }
        int range = config.getUidMax() - config.getUidMin();
        if (range <= 0) {
            throw new PosixAllocationException("invalid UID range: " + config.getUidMin()
                    + ".." + config.getUidMax());
        }

        for (int attempt = 0; attempt < config.getMaxRetries(); attempt++) {
            int uid = config.getUidMin() + random.nextInt(range);
            if (!uidInUse(uid, session, realm)) {
                return buildDetails(user, uid);
            }
        }

        throw new PosixAllocationException("failed to allocate UID for user " + user.getUsername()
                + " after " + config.getMaxRetries() + " attempts");
    }

    private boolean uidInUse(int uid, KeycloakSession session, RealmModel realm) {
        if (uidsInUseForTesting != null) {
            return uidsInUseForTesting.contains(uid);
        }
        return PosixUidInUseChecks.isInUseInKeycloakDb(session, realm, uid);
    }

    private PosixDetails buildDetails(UserModel user, int uid) {
        return buildDetails(user.getUsername(), user.getFirstAttribute(PosixAttributeNames.USERNAME), uid);
    }

    private PosixDetails buildDetails(String keycloakUsername, String presetPosixUsername, int uid) {
        String posixUsername = PosixConfig.resolvePosixUsername(presetPosixUsername, config, uid, keycloakUsername);
        String homeDirectory = PosixConfig.renderHomeDirectory(config, uid, posixUsername, keycloakUsername);
        return new PosixDetails(posixUsername, uid, uid, homeDirectory, config.getLoginShell());
    }
}
