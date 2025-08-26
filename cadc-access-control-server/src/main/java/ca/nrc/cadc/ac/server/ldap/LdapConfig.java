/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2025.                            (c) 2025.
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
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.util.MultiValuedProperties;
import ca.nrc.cadc.util.PropertiesReader;
import ca.nrc.cadc.util.StringUtil;
import java.util.Arrays;
import java.util.List;
import java.util.ServiceConfigurationError;
import org.apache.log4j.Logger;

/**
 * Reads and stores the LDAP configuration information.
 *
 * @author adriand
 */
public class LdapConfig {
    private static final Logger logger = Logger.getLogger(LdapConfig.class);

    // A temporary hack to set the LDAP config file name.
    // Refer to https://github.com/opencadc/ac/issues/60 
    public static final String CONFIG = "ac-ldap-config.properties";

    public static final String READONLY_PREFIX = "readOnly.";
    public static final String READWRITE_PREFIX = "readWrite.";
    public static final String UB_READONLY_PREFIX = "unboundReadOnly.";
    public static final String POOL_SERVERS = "servers";
    public static final String POOL_INIT_SIZE = "poolInitSize";
    public static final String POOL_MAX_SIZE = "poolMaxSize";
    public static final String POOL_POLICY = "poolPolicy";
    public static final String POOL_PORT = "port";
    public static final String POOL_SSL_PORT = "sslPort";
    public static final String MAX_WAIT = "maxWait";
    public static final String CREATE_IF_NEEDED = "createIfNeeded";

    public static final String DEFAULT_LDAP_PORT = "port";
    public static final String DEFAULT_SSL_LDAP_PORT = "sslPort";
    public static final String LDAP_SERVER_ADMIN_DN = "adminDN";
    public static final String LDAP_SERVER_ADMIN_PASSWORD = "adminPassword";
    public static final String LDAP_SERVER_PROXY_USER = "proxyUser";
    public static final String LDAP_SERVER_PROXY_PASSWORD = "proxyPassword";
    public static final String LDAP_DOMAIN_DN = "domainDN";
    public static final String LDAP_OU = "organizationalUnit";

    public enum PoolPolicy {
        roundRobin,
        fewestConnections,
        fastestConnect
    }

    public enum SystemState {
        ONLINE,
        READONLY,
        OFFLINE
    }

    // The organizational units used by AC. They are siblings.
    public enum AcUnit {
        USERS("Users"),
        SPECIAL_USERS("SpecialUsers"),
        USER_REQUESTS("UserRequests"),
        GROUPS("Groups"),
        ADMIN_GROUPS("AdminGroups");

        private final String value;

        AcUnit(String value) {
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }

        public String getDN(LdapConfig config) {
            return config.getAcOrganizationUnitDN(this);
        }
    };

    public class LdapPool {
        private List<String> servers;
        private int initSize;
        private int maxSize;
        private int port;
        private boolean sslPort = false;
        private PoolPolicy policy;
        private long maxWait;
        private boolean createIfNeeded;

        public List<String> getServers() {
            return servers;
        }

        public int getInitSize() {
            return initSize;
        }

        public int getMaxSize() {
            return maxSize;
        }

        public PoolPolicy getPolicy() {
            return policy;
        }

        public int getPort() {
            return port;
        }

        public boolean isSecure() {
            return sslPort;
        }

        public long getMaxWait() {
            return maxWait;
        }

        public boolean getCreateIfNeeded() {
            return createIfNeeded;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(" Servers: ");
            for (String server : servers) {
                sb.append(" [").append(server).append("]");
            }
            sb.append(" port: ").append(port);
            sb.append(" initSize: ").append(initSize);
            sb.append(" maxSize: ").append(maxSize);
            sb.append(" policy: ").append(policy);
            sb.append(" maxWait: ").append(maxWait);
            sb.append(" createIfNeeded: ").append(createIfNeeded);
            return sb.toString();
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof LdapPool))
                return false;

            LdapPool l = (LdapPool) other;

            if (l.port != port)
                return false;

            if (l.sslPort != sslPort)
                return false;

            if (!l.servers.equals(servers))
                return false;

            if (l.initSize != initSize)
                return false;

            if (l.maxSize != maxSize)
                return false;

            if (!(l.policy.equals(policy)))
                return false;

            if (!(l.maxWait == maxWait))
                return false;

            return l.createIfNeeded == createIfNeeded;
        }
    }

    private final LdapPool readOnlyPool = new LdapPool();
    private final LdapPool readWritePool = new LdapPool();
    private final LdapPool unboundReadOnlyPool = new LdapPool();
    private int defaultPort = -1;
    private boolean defaultSslPort = false;
    private String domainDN;
    private String organizationalUnit;
    private String adminDN;
    private String adminPasswd;
    private String proxyUser;
    private String proxyPasswd;
    private SystemState systemState;


    public String getAdminDN() {
        return adminDN;
    }

    public String getAdminPasswd() {
        return adminPasswd;
    }

    public String getProxyUser() {
        return proxyUser;
    }

    public String getProxyPasswd() {
        return proxyPasswd;
    }


    public static LdapConfig getLdapConfig() {
        return loadLdapConfig(CONFIG);
    }

    public static LdapConfig loadLdapConfig(String ldapProperties) {
        logger.debug("Reading LDAP properties from: " + ldapProperties);
        PropertiesReader pr = new PropertiesReader(ldapProperties);

        MultiValuedProperties config = pr.getAllProperties();
        if (config == null || config.keySet() == null) {
            throw new RuntimeException("failed to read any LDAP property ");
        }

        LdapConfig ldapConfig = new LdapConfig();
        if (config.getFirstPropertyValue(LDAP_SERVER_ADMIN_DN) != null) {
            ldapConfig.adminDN = getProperty(config, LDAP_SERVER_ADMIN_DN);
        }
        if (config.getFirstPropertyValue(LDAP_SERVER_ADMIN_PASSWORD) != null) {
            ldapConfig.adminPasswd = getProperty(config, LDAP_SERVER_ADMIN_PASSWORD);
        }

        loadPoolConfig(ldapConfig.readOnlyPool, config, READONLY_PREFIX);
        loadPoolConfig(ldapConfig.readWritePool, config, READWRITE_PREFIX);
        loadPoolConfig(ldapConfig.unboundReadOnlyPool, config, UB_READONLY_PREFIX);

        String defaultPort = config.getFirstPropertyValue(DEFAULT_LDAP_PORT);
        if (defaultPort != null) {
            ldapConfig.defaultPort = Integer.parseInt(defaultPort);
        }
        ldapConfig.defaultSslPort = getProperty(config, DEFAULT_SSL_LDAP_PORT).trim().equalsIgnoreCase("true");
        ldapConfig.proxyUser = getProperty(config, LDAP_SERVER_PROXY_USER);
        ldapConfig.proxyPasswd = getProperty(config, LDAP_SERVER_PROXY_PASSWORD);
        ldapConfig.domainDN = getProperty(config, LDAP_DOMAIN_DN);
        if (config.getFirstPropertyValue(LDAP_OU) != null) {
            ldapConfig.organizationalUnit = config.getFirstPropertyValue(LDAP_OU);
        } else {
            ldapConfig.organizationalUnit = "";
        }

        ldapConfig.systemState = getSystemState(ldapConfig);

        return ldapConfig;
    }

    private static void loadPoolConfig(LdapPool pool, MultiValuedProperties pr, String prefix) {
        pool.servers = getMultiProperty(pr, prefix + POOL_SERVERS);
        pool.initSize = Integer.parseInt(getProperty(pr, prefix + POOL_INIT_SIZE));
        pool.maxSize = Integer.parseInt(getProperty(pr, prefix + POOL_MAX_SIZE));
        pool.policy = PoolPolicy.valueOf(getProperty(pr, prefix + POOL_POLICY));

        // Set the port to use for this pool's servers.  Default to the parent port config so that the isSecure()
        // method still works.  Throw an Exception if no port found.
        String port = pr.getFirstPropertyValue(prefix + POOL_PORT);
        if (port == null) {
            port = pr.getFirstPropertyValue(DEFAULT_LDAP_PORT);
            if (port == null) {
                throw new ServiceConfigurationError("No port specified for " + prefix
                        + " and no default port specified at " + DEFAULT_LDAP_PORT);
            }
        }
        pool.port = Integer.parseInt(port);

        String sslPort = pr.getFirstPropertyValue(prefix + POOL_SSL_PORT);
        if (sslPort == null) {
            sslPort = pr.getFirstPropertyValue(DEFAULT_SSL_LDAP_PORT);
            if (sslPort == null) {
                throw new ServiceConfigurationError("No sslPort type specified for " + prefix
                        + " and no default sslPort type specified at " + DEFAULT_SSL_LDAP_PORT);
            }
        }
        pool.sslPort = sslPort.trim().equalsIgnoreCase("true");

        if (pool.policy == PoolPolicy.fastestConnect && !prefix.equals(READONLY_PREFIX)) {
            throw new ServiceConfigurationError(PoolPolicy.fastestConnect +
                    " pool policy cannot be applied to " +
                    prefix.substring(0, prefix.length() - 1) + " pool servers.");
        }
        pool.maxWait = Long.parseLong(getProperty(pr, prefix + MAX_WAIT));
        pool.createIfNeeded = Boolean.parseBoolean(getProperty(pr, prefix + CREATE_IF_NEEDED));
    }

    private static String getProperty(MultiValuedProperties properties, String key) {
        String prop = properties.getFirstPropertyValue(key);
        if (prop == null) {
            throw new RuntimeException("failed to read property " + key);
        }
        return prop;
    }

    private static List<String> getMultiProperty(MultiValuedProperties properties, String key) {
        String prop = getProperty(properties, key);

        if (prop.trim().isEmpty()) {
            throw new RuntimeException("failed to read property " + key);
        }

        String[] props = prop.split(" ");
        return Arrays.asList(props);
    }

    private static SystemState getSystemState(LdapConfig ldapConfig) {
        if (ldapConfig.getReadOnlyPool().getMaxSize() == 0) {
            return SystemState.OFFLINE;
        }

        if (ldapConfig.getUnboundReadOnlyPool().getMaxSize() == 0) {
            return SystemState.OFFLINE;
        }

        if (ldapConfig.getReadWritePool().getMaxSize() == 0) {
            return SystemState.READONLY;
        }

        return SystemState.ONLINE;
    }


    @Override
    public boolean equals(Object other) {
        if (!(other instanceof LdapConfig))
            return false;

        LdapConfig l = (LdapConfig) other;

        if (!(l.defaultPort == defaultPort))
            return false;

        if (!(l.domainDN.equals(domainDN)))
            return false;

        if (!(l.organizationalUnit.equals(organizationalUnit)))
            return false;

        if (!(l.proxyUser.equals(proxyUser)))
            return false;

        if (!(l.readOnlyPool.equals(readOnlyPool)))
            return false;

        if (!(l.readWritePool.equals(readWritePool)))
            return false;

        return l.unboundReadOnlyPool.equals(unboundReadOnlyPool);
    }

    private LdapConfig() {
    }

    public LdapPool getReadOnlyPool() {
        return readOnlyPool;
    }

    public LdapPool getReadWritePool() {
        return readWritePool;
    }

    public LdapPool getUnboundReadOnlyPool() {
        return unboundReadOnlyPool;
    }

    public int getDefaultPort() {
        return defaultPort;
    }

    public String getDomainDN() {
        return domainDN;
    }

    public String getOrganizationalUnit() {
        return this.organizationalUnit;
    }

    public String getOrganizationalUnitDN() {
        return StringUtil.hasText(organizationalUnit) ? "ou=" + organizationalUnit + "," + domainDN : domainDN;
    }

    private String getAcOrganizationUnitDN(AcUnit ou) {
        return this.domainDN == null ? null : "ou=" + ou.getValue() + "," + getOrganizationalUnitDN();
    }

    /**
     * Check if in read-only or offline mode.
     * <p>
     * A read max connection size of zero implies offline mode.
     * A read-wrtie max connection size of zero implies read-only mode.
     */
    public SystemState getSystemState() {
        return systemState;
    }

    public String toString() {

        return " ReadOnlyPool: [" + readOnlyPool + "]" +
                " ReadWritePool: [" + readWritePool + "]" +
                " UnboundReadOnlyPool: [" + unboundReadOnlyPool + "]" +
                " Default Port: " + defaultPort +
                " proxyUser: " + proxyUser;
    }

}
