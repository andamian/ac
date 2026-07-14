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

import java.util.Map;

/**
 * Configuration for POSIX account provisioning.
 */
public class PosixConfig {

    public static final String UID_MIN = "posix.uid.min";
    public static final String UID_MAX = "posix.uid.max";
    public static final String HOME_TEMPLATE = "posix.home.template";
    public static final String LOGIN_SHELL = "posix.login.shell";

    public static final String DEFAULT_HOME_TEMPLATE = "/home/{uid}";
    public static final String DEFAULT_LOGIN_SHELL = "/bin/nologin";
    public static final int DEFAULT_UID_MIN = 10000;
    public static final int DEFAULT_MAX_RETRIES = 25;

    private final int uidMin;
    private final int uidMax;
    private final String homeTemplate;
    private final String loginShell;
    private final int maxRetries;

    public PosixConfig(int uidMin, int uidMax, String homeTemplate, String loginShell, int maxRetries) {
        if (homeTemplate == null) {
            throw new IllegalArgumentException("homeTemplate is null");
        }
        if (loginShell == null) {
            throw new IllegalArgumentException("loginShell is null");
        }
        if (uidMin < 0) {
            throw new IllegalArgumentException("uidMin must be non-negative: " + uidMin);
        }
        if (uidMax <= uidMin) {
            throw new IllegalArgumentException("uidMax must be greater than uidMin: " + uidMax);
        }
        if (maxRetries < 1) {
            throw new IllegalArgumentException("maxRetries must be positive: " + maxRetries);
        }
        this.uidMin = uidMin;
        this.uidMax = uidMax;
        this.homeTemplate = homeTemplate;
        this.loginShell = loginShell;
        this.maxRetries = maxRetries;
    }

    public static PosixConfig fromMap(Map<String, String> config) {
        int uidMin = parseInt(getConfigValue(config, UID_MIN, String.valueOf(DEFAULT_UID_MIN)), DEFAULT_UID_MIN);
        int uidMax = parseInt(getConfigValue(config, UID_MAX, String.valueOf(Integer.MAX_VALUE)),
                Integer.MAX_VALUE);
        String homeTemplate = getConfigValue(config, HOME_TEMPLATE, DEFAULT_HOME_TEMPLATE);
        String loginShell = getConfigValue(config, LOGIN_SHELL, DEFAULT_LOGIN_SHELL);
        return new PosixConfig(uidMin, uidMax, homeTemplate, loginShell, DEFAULT_MAX_RETRIES);
    }

    public int getUidMin() {
        return uidMin;
    }

    public int getUidMax() {
        return uidMax;
    }

    public String getHomeTemplate() {
        return homeTemplate;
    }

    public String getLoginShell() {
        return loginShell;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public static String renderHomeDirectory(String template, String username, int uid) {
        return template.replace("{uid}", String.valueOf(uid)).replace("{username}", username);
    }

    private static String getConfigValue(Map<String, String> config, String key, String defaultValue) {
        if (config == null) {
            return defaultValue;
        }
        String value = config.get(key);
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        return value.trim();
    }

    private static int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }
}
