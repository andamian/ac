/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2023.                            (c) 2023.
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

package ca.nrc.cadc.ac.server.web;

import ca.nrc.cadc.ac.server.IdentityManagerImpl;
import ca.nrc.cadc.ac.server.PluginFactory;
import ca.nrc.cadc.ac.server.UserPersistence;
import ca.nrc.cadc.ac.server.web.users.AbstractUserAction;
import ca.nrc.cadc.ac.server.web.users.CreateUserAction;
import ca.nrc.cadc.ac.server.web.users.GetUserAction;
import ca.nrc.cadc.ac.server.web.users.UserActionFactory;
import ca.nrc.cadc.ac.server.web.users.UserLogInfo;
import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.IdentityManager;
import ca.nrc.cadc.auth.NotAuthenticatedException;
import ca.nrc.cadc.auth.ServletPrincipalExtractor;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.util.StringUtil;
import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

public class UserServlet extends HttpServlet {
    private static final long serialVersionUID = 5289130885807305288L;
    private static final Logger log = Logger.getLogger(UserServlet.class);

    static {
        // hard code use of internal IM
        System.setProperty(IdentityManager.class.getName(), IdentityManagerImpl.class.getName());
    }

    protected List<Subject> privilegedSubjects;

    private UserPersistence userPersistence;

    /**
     * Servlet initialization method.
     *
     * <p>
     * Receives the servlet configuration object and initializes UserPersistence
     * using input parameters read from it. Users who do augment
     * subject calls are constructed by taking the principals out of the ServletConfig
     * input parameter.
     *
     * <p>
     * The UserServlet configuration in the web deployment descriptor file
     * <code>web.xml</code> must have two input parameters:
     * <ul>
     * <li><code>ca.nrc.cadc.ac.server.web.UserServlet.PrivilegedX500Principals</code>
     * is a list of trusted administrators DNs. Each DN must be enclosed in double quotes.
     * The list can be multi-line for readability.</li>
     * <li><code>ca.nrc.cadc.ac.server.web.UserServlet.PrivilegedHttpPrincipals</code>
     * is a list of space separated userids (HTTP identities),  enclosed in double quotes,
     * corresponding to the previous DNs.</li>
     * </ul>
     * The two lists of principal names must be of the same
     * length and correspond to each other in order.
     *
     * @param config The servlet configuration object.
     * @throws javax.servlet.ServletException For general Servlet exceptions.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            String x500Users = config.getInitParameter(UserServlet.class.getName() + ".PrivilegedX500Principals");
            log.debug("PrivilegedX500Users: " + x500Users);

            String httpUsers = config.getInitParameter(UserServlet.class.getName() + ".PrivilegedHttpPrincipals");
            log.debug("PrivilegedHttpUsers: " + httpUsers);

            List<String> x500List = new ArrayList<String>();
            List<String> httpList = new ArrayList<String>();
            if (x500Users != null && httpUsers != null) {
                Pattern pattern = Pattern.compile("([^\"]\\S*|\".+?\")\\s*");
                Matcher x500Matcher = pattern.matcher(x500Users);
                Matcher httpMatcher = pattern.matcher(httpUsers);

                while (x500Matcher.find()) {
                    String next = x500Matcher.group(1);
                    x500List.add(next.replace("\"", ""));
                }

                while (httpMatcher.find()) {
                    String next = httpMatcher.group(1);
                    httpList.add(next.replace("\"", ""));
                }

                if (x500List.size() != httpList.size()) {
                    throw new RuntimeException("Init exception: Lists of augment subject principals not equivalent in length");
                }

                privilegedSubjects = new ArrayList<Subject>(x500Users.length());
                for (int i = 0; i < x500List.size(); i++) {
                    Subject s = new Subject();
                    s.getPrincipals().add(new X500Principal(x500List.get(i)));
                    s.getPrincipals().add(new HttpPrincipal(httpList.get(i)));
                    privilegedSubjects.add(s);
                }

            } else {
                log.warn("No Privileged users configured.");
            }

            PluginFactory pluginFactory = getPluginFactory();
            userPersistence = pluginFactory.createUserPersistence();
        } catch (Throwable t) {
            log.fatal("Error initializing group persistence", t);
            throw new ExceptionInInitializerError(t);
        }
    }

    @Override
    public void destroy() {
        userPersistence.destroy();
    }

    protected PluginFactory getPluginFactory() {
        return new PluginFactory();
    }

    /**
     * Create a UserAction and run the action safely.
     */
    private void doAction(UserActionFactory factory, HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        Profiler profiler = new Profiler(UserServlet.class);
        long start = System.currentTimeMillis();
        UserLogInfo logInfo = new UserLogInfo(request);

        try {
            log.info(logInfo.start());
            AbstractUserAction action = factory.createAction(request);
            log.debug("create action " + action.getClass().getSimpleName());
            action.setAcceptedContentType(getAcceptedContentType(request));
            log.debug("content-type: " + getAcceptedContentType(request));
//            profiler.checkpoint("created action");

            Subject subject;
            Subject privilegedSubject = getPrivilegedSubject(request);
            log.debug("privileged subject: " + privilegedSubject);
            if (privilegedSubject != null) {
                action.setIsPrivilegedUser(true);
                action.setPrivilegedSubject(true);
                logInfo.setSubject(privilegedSubject);
            } else {
                action.setIsPrivilegedUser(false);
                action.setPrivilegedSubject(false);
            }

            // If the calling subject is not a PrivilegedSubject,
            // AND it is a PUT request, throw an AccessControlException
            if (action instanceof CreateUserAction) {
                profiler.checkpoint("check non-privileged user");
                if (privilegedSubject == null) {
                    subject = AuthenticationUtil.getSubject(request);
                    logInfo.setSubject(subject);
                    log.debug("augmented subject: " + subject);
                    profiler.checkpoint("augment subject");
                } else {
                    log.debug("subject not augmented: " + privilegedSubject);
                    subject = privilegedSubject;
                    logInfo.setSubject(privilegedSubject);
                    profiler.checkpoint("set privileged user");
                }
            }

            // If the calling subject has a privileged X500Principal,
            // AND it is a GET request, do not augment the subject.
            else if (action instanceof GetUserAction && privilegedSubject != null) {
                subject = Subject.getSubject(AccessController.getContext());
                log.debug("subject not augmented: " + subject);
                profiler.checkpoint("set privileged user");
            } else {
                subject = AuthenticationUtil.getSubject(request);
                logInfo.setSubject(subject);
                log.debug("augmented subject: " + subject);
                profiler.checkpoint("augment subject");
            }

            SyncOutput syncOut = new SyncOutput(response);
            action.setLogInfo(logInfo);
            action.setSyncOut(syncOut);
            action.setUserPersistence(userPersistence);

            try {
                if (subject == null) {
                    action.run();
                } else {
                    Subject.doAs(subject, action);
                }
            } catch (PrivilegedActionException e) {
                Throwable cause = e.getCause();
                if (cause != null) {
                    throw cause;
                }
                Exception exception = e.getException();
                if (exception != null) {
                    throw exception;
                }
                throw e;
            } finally {
                profiler.checkpoint("Executed action");
            }
        } catch (IllegalArgumentException e) {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.getWriter().write(e.getMessage());
            response.setStatus(400);
        } catch (NotAuthenticatedException e) {
            log.debug(e.getMessage(), e);
            logInfo.setMessage(e.getMessage());
            response.getWriter().write(e.getMessage());
            response.setStatus(401);
        } catch (Throwable t) {
            String message = "Internal Server Error: " + t.getMessage();
            log.error(message, t);
            logInfo.setSuccess(false);
            logInfo.setMessage(message);
            response.getWriter().write(message);
            response.setStatus(500);
        } finally {
            profiler.checkpoint("Action complete");
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            log.info(logInfo.end());
        }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        doAction(UserActionFactory.httpGetFactory(), request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        doAction(UserActionFactory.httpPostFactory(), request, response);
    }

    @Override
    public void doDelete(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        doAction(UserActionFactory.httpDeleteFactory(), request, response);
    }

    @Override
    public void doPut(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        doAction(UserActionFactory.httpPutFactory(), request, response);
    }

    @Override
    public void doHead(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        doAction(UserActionFactory.httpHeadFactory(), request, response);
    }

    /**
     * Obtain the requested (Accept) content type.
     *
     * @param request The HTTP Request.
     * @return String content type.
     */
    String getAcceptedContentType(final HttpServletRequest request) {
        final String requestedContentType = request.getHeader("Accept");

        if (StringUtil.hasText(requestedContentType)
                && requestedContentType.contains(AbstractUserAction.JSON_CONTENT_TYPE)) {
            return AbstractUserAction.JSON_CONTENT_TYPE;
        } else {
            return AbstractUserAction.DEFAULT_CONTENT_TYPE;
        }
    }

    protected Subject getPrivilegedSubject(HttpServletRequest request) {
        if (privilegedSubjects == null || privilegedSubjects.isEmpty()) {
            return null;
        }

        ServletPrincipalExtractor extractor = new ServletPrincipalExtractor(request);
        Set<Principal> principals = extractor.getPrincipals();

        for (Principal principal : principals) {
            if (principal instanceof X500Principal) {
                for (Subject s : privilegedSubjects) {
                    Set<X500Principal> x500Principals = s.getPrincipals(X500Principal.class);
                    for (X500Principal p2 : x500Principals) {
                        if (p2.getName().equalsIgnoreCase(principal.getName())) {
                            return s;
                        }
                    }
                }
            }

            if (principal instanceof HttpPrincipal) {
                for (Subject s : privilegedSubjects) {
                    Set<HttpPrincipal> httpPrincipals = s.getPrincipals(HttpPrincipal.class);
                    for (HttpPrincipal p2 : httpPrincipals) {
                        if (p2.getName().equalsIgnoreCase(principal.getName())) {
                            return s;
                        }
                    }
                }
            }
        }

        return null;
    }
}
