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
 ************************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.rest.InitAction;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import org.apache.log4j.Logger;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;

/**
 * Utility class to setup tables in the LDAP
 *
 * @author adriand
 */
public class LdapInitAction extends InitAction {

    private static final Logger log = Logger.getLogger(LdapInitAction.class);

    private String jndiLdapUserPersistence;
    private String jndiLdapGroupPersistence;

    public LdapInitAction() {
    }

    @Override
    public void doInit() {
        log.debug("doInit: ");
        long t = System.currentTimeMillis();
        this.jndiLdapUserPersistence = appName + "-" + LdapUserPersistence.class.getName();
        try {
            Context ctx = new InitialContext();
            try {
                ctx.unbind(jndiLdapUserPersistence);
            } catch (NamingException ignore) {
                log.debug("unbind previous JNDI key (" + jndiLdapUserPersistence + ") failed... ignoring");
            }
            LdapUserPersistence lup = new LdapUserPersistence();
            ctx.bind(jndiLdapUserPersistence, lup);

            log.info("created JNDI key: " + jndiLdapUserPersistence + " impl: " + lup.getClass().getName());

        } catch (NamingException ex) {
            log.error("Failed to create JNDI Key " + jndiLdapUserPersistence, ex);
        }
        LdapConfig config = LdapConfig.getLdapConfig();

        if (config.getAdminDN() == null || config.getAdminPasswd() == null) {
            log.error("Skip init - no configured admin/passwd found");
            return;
        }

        LdapConfig.LdapPool lp = config.getReadWritePool();
        if (lp == null || lp.getServers() == null || lp.getServers().isEmpty()) {
            log.error("No LDAP server configured in LdapConfig");
            throw new RuntimeException("No LDAP server configured in LdapConfig");
        }

        try {
            LDAPConnection ldapConnection = new LDAPConnection(lp.getServers().get(0), lp.getPort(),
                    config.getAdminDN(), config.getAdminPasswd());

            if (ldapConnection.getEntry(config.getDomainDN()) == null) {
                Entry baseEntry = new Entry(config.getDomainDN());
                baseEntry.addAttribute("objectClass", "domain");
                baseEntry.addAttribute("dc", "canfar");
                ldapConnection.add(baseEntry);
            } else {
                log.debug("Domain tree already exists: " + config.getDomainDN());
            }

            if (ldapConnection.getEntry(config.getOrganizationalUnitDN()) == null) {
                log.debug("Creating organizational unit tree: " + config.getOrganizationalUnitDN());
                Entry usersEntry = new Entry(config.getOrganizationalUnitDN());
                usersEntry.addAttribute("objectClass", "organizationalUnit");
                ldapConnection.add(usersEntry);
            } else {
                log.debug("Organizational unit tree already exists: " + config.getOrganizationalUnitDN());
            }

            for (LdapConfig.AcUnit leaf : LdapConfig.AcUnit.values()) {
                String ouDN = leaf.getDN(config);
                if (ldapConnection.getEntry(ouDN) == null) {
                    log.debug("Creating tree: " + ouDN);
                    Entry entry = new Entry(ouDN);
                    entry.addAttribute("objectClass", "organizationalUnit");
                    entry.addAttribute("ou", leaf.getValue());
                    ldapConnection.add(entry);
                } else {
                    log.debug("Tree already exists: " + ouDN);
                }
            }
        } catch ( LDAPException ex) {
            log.error("Failed to create Users tree", ex);
            throw new RuntimeException("Failed to create Users tree", ex);
        }
    }
}