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

package org.opencadc.keycloak.posix.rest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.opencadc.keycloak.posix.PosixAttributeNames;
import org.opencadc.keycloak.posix.PosixProvisioner;

/**
 * Read-only lookup of POSIX user mappings from Keycloak and LDAP user stores.
 */
public final class PosixUserLookup {

    private static final int USER_PAGE_SIZE = 100;

    private PosixUserLookup() {
    }

    public static List<PosixUserMapping> lookup(KeycloakSession session, RealmModel realm,
            List<String> usernames, List<Integer> uids) {
        if (usernames.isEmpty() && uids.isEmpty()) {
            return listAll(session, realm);
        }

        Map<Integer, PosixUserMapping> results = new LinkedHashMap<>();
        for (String username : usernames) {
            PosixUserMapping mapping = findByUsername(session, realm, username);
            if (mapping == null) {
                throw new PosixUserMappingNotFoundException("user not found: " + username);
            }
            results.putIfAbsent(mapping.getUid(), mapping);
        }
        for (Integer uid : uids) {
            PosixUserMapping mapping = findByUid(session, realm, uid);
            if (mapping == null) {
                throw new PosixUserMappingNotFoundException("uid not found: " + uid);
            }
            results.putIfAbsent(mapping.getUid(), mapping);
        }
        return new ArrayList<>(results.values());
    }

    public static PosixUserMapping findByUsername(KeycloakSession session, RealmModel realm, String username) {
        if (username == null || username.trim().isEmpty()) {
            return null;
        }
        String normalized = username.trim();

        PosixUserMapping mapping = firstMapping(session.users()
                .searchForUserByUserAttributeStream(realm, PosixAttributeNames.USERNAME, normalized));
        if (mapping != null) {
            return mapping;
        }

        UserModel user = session.users().getUserByUsername(realm, normalized);
        mapping = extractMapping(user);
        if (mapping != null) {
            return mapping;
        }

        return findInLdapByAttribute(realm, session, PosixAttributeNames.LDAP_UID, normalized);
    }

    public static PosixUserMapping findByUid(KeycloakSession session, RealmModel realm, int uid) {
        PosixUserMapping mapping = firstMapping(session.users()
                .searchForUserByUserAttributeStream(realm, PosixAttributeNames.UID_NUMBER, String.valueOf(uid)));
        if (mapping != null) {
            return mapping;
        }
        return findInLdapByAttribute(realm, session, PosixAttributeNames.LDAP_UID_NUMBER, String.valueOf(uid));
    }

    public static List<PosixUserMapping> listAll(KeycloakSession session, RealmModel realm) {
        Set<Integer> seen = new LinkedHashSet<>();
        List<PosixUserMapping> mappings = new ArrayList<>();

        int first = 0;
        while (true) {
            List<UserModel> page = session.users()
                    .searchForUserStream(realm, "", first, USER_PAGE_SIZE)
                    .toList();
            if (page.isEmpty()) {
                break;
            }
            for (UserModel user : page) {
                PosixUserMapping mapping = extractMapping(user);
                if (mapping != null && seen.add(mapping.getUid())) {
                    mappings.add(mapping);
                }
            }
            if (page.size() < USER_PAGE_SIZE) {
                break;
            }
            first += USER_PAGE_SIZE;
        }

        for (LDAPStorageProvider ldapProvider : ldapProviders(realm, session)) {
            try (LDAPQuery query = LDAPUtils.createQueryForUserSearch(ldapProvider, realm)) {
                Condition condition = new LDAPQueryConditionsBuilder()
                        .present(PosixAttributeNames.LDAP_UID_NUMBER);
                query.addWhereCondition(condition);
                for (LDAPObject ldapUser : query.getResultList()) {
                    PosixUserMapping mapping = extractMapping(ldapUser);
                    if (mapping != null && seen.add(mapping.getUid())) {
                        mappings.add(mapping);
                    }
                }
            }
        }

        return mappings;
    }

    static PosixUserMapping extractMapping(UserModel user) {
        if (user == null || !PosixProvisioner.hasPosixAttributes(user)) {
            return null;
        }
        String username = user.getFirstAttribute(PosixAttributeNames.USERNAME);
        if (username == null || username.trim().isEmpty()) {
            username = user.getUsername();
        }
        return fromAttributeValues(username, user.getFirstAttribute(PosixAttributeNames.UID_NUMBER),
                user.getFirstAttribute(PosixAttributeNames.GID_NUMBER));
    }

    static PosixUserMapping extractMapping(LDAPObject ldapUser) {
        if (ldapUser == null || !PosixProvisioner.hasPosixAttributes(ldapUser)) {
            return null;
        }
        return fromAttributeValues(ldapUser.getAttributeAsString(PosixAttributeNames.LDAP_UID),
                ldapUser.getAttributeAsString(PosixAttributeNames.LDAP_UID_NUMBER),
                ldapUser.getAttributeAsString(PosixAttributeNames.LDAP_GID_NUMBER));
    }

    static PosixUserMapping fromAttributeValues(String username, String uidNumber, String gidNumber) {
        Integer uid = parsePositiveInt(uidNumber);
        if (uid == null) {
            return null;
        }
        if (username == null || username.trim().isEmpty()) {
            return null;
        }
        Integer defaultGroup = parsePositiveInt(gidNumber);
        if (defaultGroup == null) {
            defaultGroup = uid;
        }
        return new PosixUserMapping(username.trim(), uid, defaultGroup);
    }

    private static PosixUserMapping firstMapping(Stream<UserModel> users) {
        try (users) {
            return users.map(PosixUserLookup::extractMapping)
                    .filter(java.util.Objects::nonNull)
                    .findFirst()
                    .orElse(null);
        }
    }

    private static PosixUserMapping findInLdapByAttribute(RealmModel realm, KeycloakSession session,
            String ldapAttribute, String value) {
        for (LDAPStorageProvider ldapProvider : ldapProviders(realm, session)) {
            try (LDAPQuery query = LDAPUtils.createQueryForUserSearch(ldapProvider, realm)) {
                Condition condition = new LDAPQueryConditionsBuilder().equal(ldapAttribute, value);
                query.addWhereCondition(condition);
                List<LDAPObject> results = query.getResultList();
                if (results != null) {
                    for (LDAPObject ldapUser : results) {
                        PosixUserMapping mapping = extractMapping(ldapUser);
                        if (mapping != null) {
                            return mapping;
                        }
                    }
                }
            }
        }
        return null;
    }

    private static List<LDAPStorageProvider> ldapProviders(RealmModel realm, KeycloakSession session) {
        List<LDAPStorageProvider> providers = new ArrayList<>();
        realm.getComponentsStream(realm.getId(), LDAPStorageProviderFactory.PROVIDER_NAME)
                .forEach(component -> providers.add(session.getProvider(LDAPStorageProvider.class, component)));
        return providers;
    }

    private static Integer parsePositiveInt(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed >= 0 ? parsed : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
