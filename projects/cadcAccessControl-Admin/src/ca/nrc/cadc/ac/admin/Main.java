/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2014.                            (c) 2014.
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

package ca.nrc.cadc.ac.admin;

import java.io.PrintStream;
import java.security.Principal;
import java.security.cert.CertificateException;

import javax.security.auth.Subject;

import ca.nrc.cadc.ac.User;
import org.apache.log4j.Logger;

/**
 * A command line admin tool for LDAP users.
 * 
 * @author yeunga
 *
 */
public class Main
{
    private static Logger log = Logger.getLogger(Main.class);
    
    private static PrintStream systemOut = System.out;
    private static PrintStream systemErr = System.err;
 
    /**
     * Execute the specified utility.
     * @param args   The arguments passed in to this programme.
     */
    public static void main(String[] args)
    {
        try
        {
            CmdLineParser parser = new CmdLineParser(args, systemOut, systemErr);

            if (parser.proceed())
            {  
                AbstractCommand command = parser.getCommand();
                if (parser.getSubject() == null)
                {
                    // no credential, but command works with an anonymous user
                    log.debug("running as anon user");
                    command.run();
                }
                else
                {
                    Subject subject = parser.getSubject();
                    log.debug("running as " + subject);

                    // augment the subject
                    if (subject.getPrincipals().isEmpty())
                    {
                        throw new RuntimeException("BUG: subject with no principals");
                    }
                    Principal userID = subject.getPrincipals().iterator().next();
                    User<Principal> subjectUser = command.getUserPersistence().getAugmentedUser(userID);
                    for (Principal identity: subjectUser.getIdentities())
                    {
                        subject.getPrincipals().add(identity);
                    }
                    log.debug("augmented subject: " + subject);
                    Subject.doAs(subject, command);
                }
            }
            else
            {
                systemOut.println(CmdLineParser.getUsage());
            }
        }
        catch(UsageException e)
        {
            systemErr.println("ERROR: " + e.getMessage());
    		systemOut.println(CmdLineParser.getUsage());
            System.exit(0);
        }
        catch(CertificateException e)
        {
            systemErr.println("ERROR: " + e.getMessage());
            e.printStackTrace(systemErr);
            System.exit(0);
        }
        catch(Throwable t)
        {
            systemErr.println("ERROR: " + t.getMessage());
            t.printStackTrace(systemErr);
            System.exit(-1);
        }
    }
}
