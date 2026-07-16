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

import jakarta.enterprise.inject.Vetoed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * OpenCADC UMS REST endpoints for VOSI capabilities and POSIX user mapping lookup.
 */
@Vetoed
@Path("/")
public class PosixUmsResource {

    private final KeycloakSession session;
    private final PosixUmsConfig config;

    public PosixUmsResource(KeycloakSession session, PosixUmsConfig config) {
        this.session = session;
        this.config = config;
    }

    @GET
    @Path("capabilities")
    @Produces(MediaType.APPLICATION_XML)
    public Response getCapabilities() {
        String document = PosixCapabilitiesBuilder.build(config);
        return Response.ok(document).build();
    }

    @GET
    @Path("uid")
    public Response getUidMappings(@QueryParam("user") List<String> users,
            @QueryParam("uid") List<String> uidParams,
            @Context HttpHeaders headers) {
        requireBearerToken(headers);

        RealmModel realm = session.getContext().getRealm();
        List<String> usernames = normalizeQueryValues(users);
        List<Integer> uids = parseUidParameters(uidParams);

        boolean tsv = PosixUserMappingFormatter.isTsv(headers.getHeaderString(HttpHeaders.ACCEPT));
        try {
            List<PosixUserMapping> mappings = PosixUserLookup.lookup(session, realm, usernames, uids);
            String body = PosixUserMappingFormatter.format(mappings, tsv);
            return Response.ok(body)
                    .type(tsv ? PosixUserMappingFormatter.TSV_CONTENT_TYPE
                            : PosixUserMappingFormatter.PLAIN_CONTENT_TYPE)
                    .build();
        } catch (PosixUserMappingNotFoundException ex) {
            throw new NotFoundException(ex.getMessage(), ex);
        }
    }

    private void requireBearerToken(HttpHeaders headers) {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(session.getContext().getRealm())
                .setUriInfo(session.getContext().getUri())
                .setConnection(session.getContext().getConnection())
                .setHeaders(headers)
                .setRequest(session.getContext().getHttpRequest())
                .authenticate();
        if (authResult == null) {
            throw new NotAuthorizedException("Bearer");
        }
    }

    private static List<String> normalizeQueryValues(List<String> values) {
        List<String> normalized = new ArrayList<>();
        if (values == null) {
            return normalized;
        }
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                normalized.add(value.trim());
            }
        }
        return normalized;
    }

    private static List<Integer> parseUidParameters(List<String> uidParams) {
        List<Integer> uids = new ArrayList<>();
        if (uidParams == null) {
            return uids;
        }
        for (String uidParam : uidParams) {
            if (uidParam == null || uidParam.trim().isEmpty()) {
                continue;
            }
            try {
                uids.add(Integer.parseInt(uidParam.trim()));
            } catch (NumberFormatException ex) {
                throw new NotFoundException("uid not found: " + uidParam);
            }
        }
        return uids;
    }
}
