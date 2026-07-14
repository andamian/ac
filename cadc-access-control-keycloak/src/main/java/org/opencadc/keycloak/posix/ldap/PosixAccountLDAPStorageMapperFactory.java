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

package org.opencadc.keycloak.posix.ldap;

import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.LDAPConfigDecorator;
import org.opencadc.keycloak.posix.PosixConfig;

/**
 * Factory for the OpenCADC POSIX account LDAP mapper.
 */
public class PosixAccountLDAPStorageMapperFactory extends AbstractLDAPStorageMapperFactory
        implements LDAPConfigDecorator {

    public static final String PROVIDER_ID = "opencadc-posix-account";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = buildConfigProperties();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Assigns POSIX account attributes (uid, uidNumber, gidNumber, homeDirectory, loginShell) "
                + "when Keycloak registers a new user in LDAP.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel,
            LDAPStorageProvider federationProvider) {
        return new PosixAccountLDAPStorageMapper(mapperModel, federationProvider);
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
    }

    @Override
    public void updateLDAPConfig(LDAPConfig ldapConfig, ComponentModel mapperModel) {
    }

    private static List<ProviderConfigProperty> buildConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(PosixConfig.UID_MIN)
                .label("Minimum UID")
                .helpText("Lower bound for allocated UIDs")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(PosixConfig.DEFAULT_UID_MIN))
                .add()
                .property().name(PosixConfig.UID_MAX)
                .label("Maximum UID")
                .helpText("Upper bound for allocated UIDs")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(String.valueOf(Integer.MAX_VALUE))
                .add()
                .property().name(PosixConfig.USERS_HOME)
                .label("Users home base directory")
                .helpText("Base directory for home paths; used by the {usersHome} placeholder")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(PosixConfig.DEFAULT_USERS_HOME)
                .add()
                .property().name(PosixConfig.USERNAME_TEMPLATE)
                .label("POSIX username template")
                .helpText("Used when posix.username is not already set; supports {uid} and {keycloakUsername}")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(PosixConfig.DEFAULT_USERNAME_TEMPLATE)
                .add()
                .property().name(PosixConfig.HOME_TEMPLATE)
                .label("Home directory template")
                .helpText("Supports {usersHome}, {username}, {uid}, and {keycloakUsername} placeholders")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(PosixConfig.DEFAULT_HOME_TEMPLATE)
                .add()
                .property().name(PosixConfig.LOGIN_SHELL)
                .label("Login shell")
                .helpText("Value for the loginShell attribute")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(PosixConfig.DEFAULT_LOGIN_SHELL)
                .add()
                .build();
    }
}
