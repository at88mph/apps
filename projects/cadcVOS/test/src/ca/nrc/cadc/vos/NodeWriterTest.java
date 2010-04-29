/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONN�ES ASTRONOMIQUES  **************
 *
 *  (c) 2009.                            (c) 2009.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits r�serv�s
 *
 *  NRC disclaims any warranties,        Le CNRC d�nie toute garantie
 *  expressed, implied, or               �nonc�e, implicite ou l�gale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           �tre tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou g�n�ral,
 *  arising from the use of the          accessoire ou fortuit, r�sultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        �tre utilis�s pour approuver ou
 *  products derived from this           promouvoir les produits d�riv�s
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  pr�alable et particuli�re
 *                                       par �crit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la �GNU Affero General Public
 *  License as published by the          License� telle que publi�e
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (� votre gr�)
 *  any later version.                   toute version ult�rieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribu�
 *  hope that it will be useful,         dans l�espoir qu�il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans m�me la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILIT�
 *  or FITNESS FOR A PARTICULAR          ni d�AD�QUATION � UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           G�n�rale Publique GNU Affero
 *  more details.                        pour plus de d�tails.
 *
 *  You should have received             Vous devriez avoir re�u une
 *  a copy of the GNU Affero             copie de la Licence G�n�rale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n�est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.vos;

import ca.nrc.cadc.util.Log4jInit;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jburke
 */
public class NodeWriterTest
{
private static Logger log = Logger.getLogger(NodeWriterTest.class);
    {
        Log4jInit.setLevel("ca", Level.INFO);
    }

    static ContainerNode containerNode;
    static DataNode dataNode;

    public NodeWriterTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        // List of NodeProperty
        List<NodeProperty> properties = new ArrayList<NodeProperty>();
        NodeProperty nodeProperty = new NodeProperty("ivo://ivoa.net/vospace/core#description", "My award winning images");
        nodeProperty.setReadOnly(true);
        properties.add(nodeProperty);

        // List of Node
        List<Node> nodes = new ArrayList<Node>();
        nodes.add(new DataNode("vos://nvo.caltech!vospace/mydir/ngc4323"));
        nodes.add(new DataNode("vos://nvo.caltech!vospace/mydir/ngc5796"));
        nodes.add(new DataNode("vos://nvo.caltech!vospace/mydir/ngc6801"));

        // ContainerNode
        containerNode = new ContainerNode("/dir/subdir", properties);
        containerNode.setNodes(nodes);

        // DataNode
        dataNode = new DataNode("/dir/subdir", properties);
        dataNode.setBusy(true);
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of write method, of class NodeWriter.
     */
    @Test
    public void write_ContainerNode_StringBuilder()
    {
        try
        {
            log.debug("write_ContainerNode_StringBuilder");
            StringBuilder sb = new StringBuilder();
            NodeWriter instance = new NodeWriter();
            instance.write(containerNode, sb);
            log.debug(sb.toString());
            log.info("write_ContainerNode_StringBuilder passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

    @Test
    public void write_DataNode_StringBuilder()
    {
        try
        {
            log.debug("write_DataNode_StringBuilder");
            StringBuilder sb = new StringBuilder();
            NodeWriter instance = new NodeWriter();
            instance.write(dataNode, sb);
            log.debug(sb.toString());
            log.info("write_DataNode_StringBuilder passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

    /**
     * Test of write method, of class NodeWriter.
     */
    @Test
    public void write_ContainerNode_OutputStream()
    {
        try
        {
            log.debug("write_ContainerNode_OutputStream");
            NodeWriter instance = new NodeWriter();
            instance.write(containerNode, System.out);
            log.info("write_ContainerNode_OutputStream passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

    /**
     * Test of write method, of class NodeWriter.
     */
    @Test
    public void write_DataNode_OutputStream()
    {
        try
        {
            log.debug("write_DataNode_OutputStream");
            NodeWriter instance = new NodeWriter();
            instance.write(dataNode, System.out);
            log.info("write_DataNode_OutputStream passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

    /**
     * Test of write method, of class NodeWriter.
     */
    @Test
    public void write_ContainerNode_Writer()
    {
        try
        {
            log.debug("write_ContainerNode_Writer");
            NodeWriter instance = new NodeWriter();
            instance.write(containerNode, new OutputStreamWriter(System.out, "UTF-8"));
            log.info("write_ContainerNode_Writer passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

    /**
     * Test of write method, of class NodeWriter.
     */
    @Test
    public void write_DataNode_Writer()
    {
        try
        {
            log.debug("write_DataNode_Writer");
            NodeWriter instance = new NodeWriter();
            instance.write(dataNode, new OutputStreamWriter(System.out, "UTF-8"));
            log.info("write_DataNode_Writer passed");
        }
        catch (Throwable t)
        {
            log.error(t);
            fail(t.getMessage());
        }
    }

}