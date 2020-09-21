
/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2020.                            (c) 2020.
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
 *
 ************************************************************************
 */

package ca.nrc.cadc.dlm;

import ca.nrc.cadc.dali.util.ShapeFormat;
import ca.nrc.cadc.util.Log4jInit;
import java.net.URI;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

public class DownloadTupleTest {
    private static Logger log = Logger.getLogger(DownloadTupleTest.class);
    private static String URI_STR = "test://mysite.ca/path/1";
    private static String SHAPE_STR = "polygon 0 0 0 0 0";
    private static String LABEL_STR = "label";
    private ShapeFormat sf = new ShapeFormat();

    // test://mysite.ca/path/1{polygon 0 0 0 0}
    private static String TUPLE_INTERNAL_SHAPE = URI_STR + "{" + SHAPE_STR + "}";

    // test://mysite.ca/path/1{polygon 0 0 0 0}{label}
    private static String TUPLE_INTERNAL = TUPLE_INTERNAL_SHAPE + "{" + LABEL_STR + "}";

    static {
        Log4jInit.setLevel("ca.nrc.cadc", Level.DEBUG);
    }

    // TODO: all the parsingError stuff needs to be reworked...
    @Test
    public void testFormatsURIOnly() throws Exception {
        DownloadTuple dt = new DownloadTuple(new URI(URI_STR), null, null);
        log.debug("internal format, uri only: " + dt.toInternalFormat());
        Assert.assertEquals("invalid internal tuple format", dt.toInternalFormat(), URI_STR);
//        Assert.assertTrue("DownloadTuple ctor failed parsing tupleID.", (dt.parsingError == null) );
    }

    @Test
    public void testFormat() throws Exception {
        DownloadTuple dt = new DownloadTuple(new URI(URI_STR), sf.parse(SHAPE_STR), LABEL_STR);
        log.debug("internal format, full: " + dt.toInternalFormat());
        Assert.assertEquals("invalid internal tuple format", dt.toInternalFormat(), TUPLE_INTERNAL);
//        Assert.assertTrue("DownloadTuple ctor failed parsing tupleID.", (dt.parsingError == null) );
    }

    @Test
    public void testFormatNoLabel() throws Exception {
        DownloadTuple dt = new DownloadTuple(new URI(URI_STR), sf.parse(SHAPE_STR), null);
        log.debug("internal format, no label: " + dt.toInternalFormat());
        Assert.assertEquals("invalid internal tuple format", dt.toInternalFormat(), TUPLE_INTERNAL_SHAPE);
//        Assert.assertTrue("DownloadTuple ctor failed parsing tupleID.", (dt.parsingError == null) );
    }

    @Test
    public void testInvalidNullURI() throws Exception {
        DownloadTuple dt = new DownloadTuple(null, null, null);
//        log.debug("parsing error: " + dt.parsingError);
//        Assert.assertTrue("DownloadTuple ctor should have failed for null parameter", (dt.parsingError != null) );
    }

    @Test
    public void testInvalidURI() throws Exception {
//        DownloadTuple dt = new DownloadTuple("bad_URI_format has spaces");
//        log.debug("parsing error: " + dt.parsingError);
//        Assert.assertTrue("DownloadTuple ctor should have failed for null parameter", (dt.parsingError != null));
    }
}
