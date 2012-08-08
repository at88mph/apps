/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2009.                            (c) 2009.
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


package ca.nrc.cadc.dlm.server;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ca.nrc.cadc.auth.SSOCookieManager;
import ca.nrc.cadc.dlm.DownloadUtil;
import ca.nrc.cadc.net.NetUtil;
import ca.nrc.cadc.util.ArrayUtil;
import org.apache.log4j.Logger;

/**
 * Download pre-processor. This servlet accepts either direct POSTs from clients or
 * requerst scope attributes and passes the request on to the approproate JSP page.
 * </p><p>
 * For direct POST, the client must use the multi-valued <em>uri</em> parameter to pass 
 * in one or more URIs. These are flattened into a single comma-separated list and 
 * passed along as attributes. The client may also set the single-valued <em>fragment</em>
 * parameter; the fragment is appended to each URI before SchemeHandler(s) are used to
 * convert them to URLs.
 * </p><p>
 * When forwarding from another servlet
 * @author pdowler
 */
public class DownloadServlet extends HttpServlet
{
    private static final long serialVersionUID = 201208071730L;
    
    private static final Logger log = Logger.getLogger(DownloadServlet.class);

    /**
     * 
     * @param config
     * @throws javax.servlet.ServletException
     */
    public void init(ServletConfig config)
        throws ServletException
    {
        super.init(config);
    }
    
    /**
     * Handle POSTed download request from an external page.
     * 
     * @param request
     * @param response
     * @throws javax.servlet.ServletException
     * @throws java.io.IOException
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException
    {
        boolean empty = true;

        // check for forwarded attributes
        String fragment = (String) request.getAttribute("fragment");
        String uris = (String) request.getAttribute("uris");
        log.debug("fragment attribute: " + fragment);
        log.debug("uris attribute: " + uris);
        
        // check for direct POST
        if (uris == null)
        {
            log.debug("checking for uris parameter...");
            uris = request.getParameter("uris"); // forward/render of JSP page
            
            if (uris == null)
            {
                log.debug("checking for uri parameter...");
                String[] uri = request.getParameterValues("uri");
                if (uri != null)
                {
                    uris = DownloadUtil.flattenURIs(uri);
                    log.debug("found " + uri.length + " uri parameters: " + uris);
                }
            }
            if (uris != null)
            {
                log.debug("adding request attribute: uris=" + uris);
                request.setAttribute("uris", uris);
                empty = false;
            }
        }
        else
            empty = false;
        
        if (fragment == null)
        {
            log.debug("checking for fragment parameter...");
            fragment = request.getParameter("fragment");
            if (fragment != null)
            {
                log.debug("adding request attribute: fragment=" + fragment);
                request.setAttribute("fragment", fragment);
            }
        }
        
        if (empty)
        {
             request.getRequestDispatcher("/emptySubmit.jsp").forward(request, response);
             return;
        }
        
        // check for preferred/selected download method
        String target = ServerUtil.getDownloadMethod(request, response);
        if (target == null)
            target = "/chooser.jsp";
                    
        // codebase for applet and webstart deployments
        String codebase = ServerUtil.getCodebase(request);
        request.setAttribute("codebase", codebase);
        log.debug("codebase attribute: " + codebase);
        
        // origin serverName for applet and jnlp deployment
        String  serverName = NetUtil.getServerName(DownloadServlet.class);
        request.setAttribute("serverName", serverName);
        log.debug("serverName attribute: " + serverName);
        
        log.debug("looking for ssocookie attribute...");
        final Cookie[] cookies = request.getCookies();
        if (!ArrayUtil.isEmpty(cookies))
        {
            for (final Cookie cookie : cookies)
            {
                if (cookie.getName().equals(
                        SSOCookieManager.DEFAULT_SSO_COOKIE_NAME))
                {
                    request.setAttribute("ssocookie", cookie.getValue());
                    log.debug("ssocookie attribute: " + cookie.getValue());
                    request.setAttribute("ssocookiedomain", 
                            NetUtil.getDomainName(request.getRequestURL().toString()));
                    log.debug("ssocookie domain: " + 
                            NetUtil.getDomainName(request.getRequestURL().toString()));
                }
            }
        }
        

        RequestDispatcher disp = request.getRequestDispatcher(target);
        disp.forward(request, response);
    }
    
}
