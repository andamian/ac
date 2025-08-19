/**
 * ***********************************************************************
 * ******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 * *************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 * <p>
 * (c) 2019.                            (c) 2019.
 * Government of Canada                 Gouvernement du Canada
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits réservés
 * <p>
 * NRC disclaims any warranties,        Le CNRC dénie toute garantie
 * expressed, implied, or               énoncée, implicite ou légale,
 * statutory, of any kind with          de quelque nature que ce
 * respect to the software,             soit, concernant le logiciel,
 * including without limitation         y compris sans restriction
 * any warranty of merchantability      toute garantie de valeur
 * or fitness for a particular          marchande ou de pertinence
 * purpose. NRC shall not be            pour un usage particulier.
 * liable in any event for any          Le CNRC ne pourra en aucun cas
 * damages, whether direct or           être tenu responsable de tout
 * indirect, special or general,        dommage, direct ou indirect,
 * consequential or incidental,         particulier ou général,
 * arising from the use of the          accessoire ou fortuit, résultant
 * software.  Neither the name          de l'utilisation du logiciel. Ni
 * of the National Research             le nom du Conseil National de
 * Council of Canada nor the            Recherches du Canada ni les noms
 * names of its contributors may        de ses  participants ne peuvent
 * be used to endorse or promote        être utilisés pour approuver ou
 * products derived from this           promouvoir les produits dérivés
 * software without specific prior      de ce logiciel sans autorisation
 * written permission.                  préalable et particulière
 * par écrit.
 * <p>
 * This file is part of the             Ce fichier fait partie du projet
 * OpenCADC project.                    OpenCADC.
 * <p>
 * OpenCADC is free software:           OpenCADC est un logiciel libre ;
 * you can redistribute it and/or       vous pouvez le redistribuer ou le
 * modify it under the terms of         modifier suivant les termes de
 * the GNU Affero General Public        la “GNU Affero General Public
 * License as published by the          License” telle que publiée
 * Free Software Foundation,            par la Free Software Foundation
 * either version 3 of the              : soit la version 3 de cette
 * License, or (at your option)         licence, soit (à votre gré)
 * any later version.                   toute version ultérieure.
 * <p>
 * OpenCADC is distributed in the       OpenCADC est distribué
 * hope that it will be useful,         dans l’espoir qu’il vous
 * but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 * without even the implied             GARANTIE : sans même la garantie
 * warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 * or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 * PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 * General Public License for           Générale Publique GNU Affero
 * more details.                        pour plus de détails.
 * <p>
 * You should have received             Vous devriez avoir reçu une
 * a copy of the GNU Affero             copie de la Licence Générale
 * General Public License along         Publique GNU Affero avec
 * with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 * <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 * <http://www.gnu.org/licenses/>.
 * <p>
 * ***********************************************************************
 */

package ca.nrc.cadc.ac.server.ldap;

import ca.nrc.cadc.ac.PersonalDetails;
import ca.nrc.cadc.ac.User;
import ca.nrc.cadc.ac.UserNotFoundException;
import ca.nrc.cadc.ac.UserRequest;
import ca.nrc.cadc.auth.DNPrincipal;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.util.Log4jInit;
import java.lang.reflect.Field;
import java.util.NoSuchElementException;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;

/**
 * Created by jburke on 2014-11-03.
 */
public class AbstractLdapDAOTest {
    private static final Logger log = Logger.getLogger(AbstractLdapDAOTest.class);

    static final String CONFIG = "ac-ldap-config.test.properties";

    protected static final String SERVOPS_PEM = System.getProperty("user.home") + "/.pub/proxy.pem";
    static final String cadcDaoTest1_CN = "CadcDaoTest1";
    static final String cadcDaoTest2_CN = "CadcDaoTest2";
    static final String cadcDaoTest3_CN = "CadcDaoTest3";
    static final String cadcDaoTest1_X500DN = "cn=cadcdaotest1,ou=cadc,o=hia,c=ca";
    static final String cadcDaoTest2_X500DN = "cn=cadcdaotest2,ou=cadc,o=hia,c=ca";
    static final String cadcDaoTest3_X500DN = "cn=cadcdaotest3,ou=cadc,o=hia,c=ca";

    static User cadcDaoTest1_User;
    static User cadcDaoTest2_User;
    static User cadcDaoTest3_User;
    static User cadcDaoTest1_AugmentedUser;
    static User cadcDaoTest2_AugmentedUser;
    static User testMember;

    static String cadcDaoTest1_DN;
    static String cadcDaoTest2_DN;

    static HttpPrincipal cadcDaoTest1_HttpPrincipal;
    static HttpPrincipal cadcDaoTest2_HttpPrincipal;
    static HttpPrincipal cadcDaoTest3_HttpPrincipal;
    static X500Principal cadcDaoTest1_X500Principal;
    static X500Principal cadcDaoTest2_X500Principal;
    static X500Principal cadcDaoTest3_X500Principal;
    static DNPrincipal cadcDaoTest1_DNPrincipal;
    static DNPrincipal cadcDaoTest2_DNPrincipal;

    static Subject cadcDaoTest1_Subject;
    static Subject cadcDaoTest2_Subject;

    static LdapConfig config;

    static LdapConnections connections;

    @BeforeClass
    public static void setUpBeforeClass()
            throws Exception {
        Log4jInit.setLevel("ca.nrc.cadc.ac", Level.INFO);
        Log4jInit.setLevel("ca.nrc.cadc.util", Level.INFO);

        //System.setProperty(PropertiesReader.class.getName() + ".dir", "src/test/resources");

        try {
            // get the configuration of the development server from and config files...
            try {
                config = getLdapConfig();
                connections = new LdapConnections(config);
            } catch (NoSuchElementException e) {
                log.warn("Skipping integration test: no entry in ~/.dbrc file");
                org.junit.Assume.assumeTrue(false);
                return;
            } catch (RuntimeException e) {
                log.warn("Skipping integration test", e);
                org.junit.Assume.assumeTrue(false);
                return;
            }
            cadcDaoTest1_HttpPrincipal = new HttpPrincipal(cadcDaoTest1_CN);
            cadcDaoTest2_HttpPrincipal = new HttpPrincipal(cadcDaoTest2_CN);
            cadcDaoTest3_HttpPrincipal = new HttpPrincipal(cadcDaoTest3_CN);

            cadcDaoTest1_X500Principal = new X500Principal(cadcDaoTest1_X500DN);
            cadcDaoTest2_X500Principal = new X500Principal(cadcDaoTest2_X500DN);
            cadcDaoTest3_X500Principal = new X500Principal(cadcDaoTest3_X500DN);

            try {
                cadcDaoTest1_User = getUserDAO().getUser(cadcDaoTest1_HttpPrincipal);
            } catch (UserNotFoundException e) {
                try {
                    cadcDaoTest1_User = getUserDAO().getUserRequest(cadcDaoTest1_HttpPrincipal);
                } catch (UserNotFoundException ex) {
                    User user = new User();
                    user.getIdentities().add(cadcDaoTest1_HttpPrincipal);
                    user.getIdentities().add(cadcDaoTest1_X500Principal);
                    user.personalDetails = new PersonalDetails("CADC", "DAOTest1");
                    user.personalDetails.email = cadcDaoTest1_CN + "@canada.ca";
                    UserRequest userRequest = new UserRequest(user, "password".toCharArray());
                    getUserDAO().addUserRequest(userRequest);
                }

                getUserDAO().approveUserRequest(cadcDaoTest1_HttpPrincipal);
                cadcDaoTest1_User = getUserDAO().getUser(cadcDaoTest1_HttpPrincipal);
            }

            try {
                cadcDaoTest2_User = getUserDAO().getUser(cadcDaoTest2_HttpPrincipal);
            } catch (UserNotFoundException e) {
                try {
                    cadcDaoTest2_User = getUserDAO().getUserRequest(cadcDaoTest2_HttpPrincipal);
                } catch (UserNotFoundException ex) {
                    User user = new User();
                    user.getIdentities().add(cadcDaoTest2_HttpPrincipal);
                    user.getIdentities().add(cadcDaoTest2_X500Principal);
                    user.personalDetails = new PersonalDetails("CADC", "DAOTest2");
                    user.personalDetails.email = cadcDaoTest2_CN + "@canada.ca";
                    UserRequest userRequest = new UserRequest(user, "password".toCharArray());
                    getUserDAO().addUserRequest(userRequest);
                }

                getUserDAO().approveUserRequest(cadcDaoTest2_HttpPrincipal);
                cadcDaoTest2_User = getUserDAO().getUser(cadcDaoTest2_HttpPrincipal);
            }

            try {
                cadcDaoTest3_User = getUserDAO().getUser(cadcDaoTest3_HttpPrincipal);
            } catch (UserNotFoundException e) {
                try {
                    cadcDaoTest3_User = getUserDAO().getUserRequest(cadcDaoTest3_HttpPrincipal);
                } catch (UserNotFoundException ex) {
                    User user = new User();
                    user.getIdentities().add(cadcDaoTest3_HttpPrincipal);
                    user.getIdentities().add(cadcDaoTest3_X500Principal);
                    user.personalDetails = new PersonalDetails("CADC", "DAOTest3");
                    user.personalDetails.email = cadcDaoTest3_CN + "@canada.ca";
                    UserRequest userRequest = new UserRequest(user, "password".toCharArray());
                    getUserDAO().addUserRequest(userRequest);
                }

                getUserDAO().approveUserRequest(cadcDaoTest3_HttpPrincipal);
                cadcDaoTest3_User = getUserDAO().getUser(cadcDaoTest3_HttpPrincipal);
            }

            // cadcDaoTest1 User and Subject with all Principals
            cadcDaoTest1_AugmentedUser = getUserDAO().getAugmentedUser(cadcDaoTest1_HttpPrincipal, true);
            cadcDaoTest1_Subject = new Subject();
            cadcDaoTest1_Subject.getPrincipals().addAll(cadcDaoTest1_AugmentedUser.getIdentities());

            // cadcDaoTest2 User and Subject with all Principals
            cadcDaoTest2_AugmentedUser = getUserDAO().getAugmentedUser(cadcDaoTest2_HttpPrincipal, true);
            cadcDaoTest2_Subject = new Subject();
            cadcDaoTest2_Subject.getPrincipals().addAll(cadcDaoTest2_AugmentedUser.getIdentities());

            // member returned by getMember contains only the fields required by the GMS
            testMember = new User();
            testMember.personalDetails = new PersonalDetails("test", "member");
            testMember.getIdentities().add(cadcDaoTest1_X500Principal);
            testMember.getIdentities().add(cadcDaoTest1_HttpPrincipal);

            // entryDN
            cadcDaoTest1_DN = "uid=cadcdaotest1," + LdapConfig.AcUnit.USER_REQUESTS.getDN(config);
            cadcDaoTest2_DN = "uid=cadcdaotest2," + LdapConfig.AcUnit.USER_REQUESTS.getDN(config);

            cadcDaoTest1_DNPrincipal = new DNPrincipal(cadcDaoTest1_DN);
            cadcDaoTest2_DNPrincipal = new DNPrincipal(cadcDaoTest2_DN);
        } catch (Exception oops) {
            log.error("setup failed", oops);
            throw oops;
        }
    }

    static LdapUserDAO getUserDAO() throws Exception {
        return new LdapUserDAO(connections);
    }

    LdapGroupDAO getGroupDAO() throws Exception {
        return new LdapGroupDAO(connections,
                new LdapUserDAO(connections));
    }

    static protected LdapConfig getLdapConfig() throws Exception {
        return LdapConfig.loadLdapConfig(CONFIG);
    }

    public static void setField(Object object, Object value, String name)
            throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(object, value);
    }

}
