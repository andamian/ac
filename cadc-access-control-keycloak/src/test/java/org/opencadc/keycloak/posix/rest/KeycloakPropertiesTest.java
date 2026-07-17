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

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.Config;
import org.opencadc.keycloak.posix.PosixConfig;
import org.opencadc.keycloak.posix.PosixIssPrefixConfigResolver;

public class KeycloakPropertiesTest {

    private static final String SAMPLE_RESOURCE = "/keycloak.properties";
    private static final String UMS_SPI_PREFIX = "spi-realm-restapi-extension-posix-";
    private static final String LISTENER_SPI_PREFIX = "spi-events-listener--opencadc-posix--";

    @Test
    public void testSampleKeycloakPropertiesConfigureUms() throws IOException {
        Properties properties = loadSampleProperties();

        Assert.assertEquals("/ums", properties.getProperty("http-relative-path"));

        PosixUmsConfig config = PosixUmsConfig.fromScope(umsExtensionScope(properties));
        Assert.assertEquals("http://localhost:8080/ums", config.getPublicBaseUrl());
        Assert.assertEquals(
                "http://localhost:8080/ums/realms/master/posix/uid",
                config.getUidAccessUrl());

        String capabilities = PosixCapabilitiesBuilder.build(config);
        Assert.assertTrue(capabilities.contains("http://localhost:8080/ums/capabilities</accessURL>"));
        Assert.assertTrue(capabilities.contains(
                "http://localhost:8080/ums/realms/master/posix/uid</accessURL>"));
    }

    @Test
    public void testSampleKeycloakPropertiesConfigureEventListenerIssPrefixes() throws IOException {
        Properties properties = loadSampleProperties();

        String issPrefixes = properties.getProperty(LISTENER_SPI_PREFIX + "posix-username-iss-prefixes");
        Assert.assertNotNull("sample keycloak.conf must define iss-prefixes with dashed property name", issPrefixes);

        Map<String, String> values = new HashMap<>();
        values.put(PosixConfig.ISS_PREFIXES, issPrefixes);
        PosixConfig config = PosixConfig.fromMap(values);
        Assert.assertEquals("ska",
                config.getIssuerUsernamePrefix("https://ska-iam.stfc.ac.uk/").orElse(null));

        Assert.assertEquals(PosixIssPrefixConfigResolver.KEYCLOAK_CONF_ISS_PREFIXES,
                LISTENER_SPI_PREFIX + "posix-username-iss-prefixes");
    }

    private static Properties loadSampleProperties() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = KeycloakPropertiesTest.class.getResourceAsStream(SAMPLE_RESOURCE)) {
            Assert.assertNotNull("sample keycloak.properties must be on the test classpath", input);
            properties.load(input);
        }
        return properties;
    }

    private static Config.Scope umsExtensionScope(Properties properties) {
        return new Config.Scope() {
            @Override
            public String get(String key) {
                return properties.getProperty(UMS_SPI_PREFIX + key);
            }

            @Override
            public String get(String key, String defaultValue) {
                return properties.getProperty(UMS_SPI_PREFIX + key, defaultValue);
            }

            @Override
            public String[] getArray(String key) {
                return new String[0];
            }

            @Override
            public Integer getInt(String key, Integer defaultValue) {
                return defaultValue;
            }

            @Override
            public Long getLong(String key, Long defaultValue) {
                return defaultValue;
            }

            @Override
            public Boolean getBoolean(String key, Boolean defaultValue) {
                return defaultValue;
            }

            @Override
            public Config.Scope scope(String... scope) {
                return this;
            }

            @Override
            public Set<String> getPropertyNames() {
                return Collections.emptySet();
            }

            @Override
            public Config.Scope root() {
                return this;
            }
        };
    }
}
