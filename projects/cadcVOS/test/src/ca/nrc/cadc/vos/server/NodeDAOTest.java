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

package ca.nrc.cadc.vos.server;

import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.security.Principal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.X500IdentityManager;
import ca.nrc.cadc.date.DateUtil;
import ca.nrc.cadc.db.ConnectionConfig;
import ca.nrc.cadc.db.DBConfig;
import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.util.FileMetadata;
import ca.nrc.cadc.util.HexUtil;
import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.vos.ContainerNode;
import ca.nrc.cadc.vos.DataNode;
import ca.nrc.cadc.vos.Node;
import ca.nrc.cadc.vos.NodeProperty;
import ca.nrc.cadc.vos.VOS;
import ca.nrc.cadc.vos.VOSURI;
import ca.nrc.cadc.vos.VOS.NodeBusyState;
import ca.nrc.cadc.vos.server.NodeDAO.NodeSchema;


/**
 * Test class for the NodeDAO class in cadcVOS.
 * 
 * @author pdowler
 *
 */
public class NodeDAOTest
{   
    private static Logger log = Logger.getLogger(NodeDAOTest.class);

    static final String SERVER = "VOSPACE_WS_TEST";
    static final String DATABASE = "cadctest";

    static final String VOS_AUTHORITY = "cadc.nrc.ca!vospace";
    static final String HOME_CONTAINER = "CADCRegtest1";
    static final String NODE_OWNER =  "CN=CADC Regtest1 10577,OU=CADC,O=HIA";
    static final String NODE_OWNER2 = "CN=CADC Authtest1 10627,OU=CADC,O=HIA";

    protected Subject owner;
    protected Subject owner2;
    protected Principal principal;
    protected Principal principal2;

    static
    {
        Log4jInit.setLevel("ca.nrc.cadc", Level.INFO);
    }
    
    DataSource dataSource;
    NodeDAO nodeDAO;
    String runID;

    public NodeDAOTest() throws Exception
    {
        this.runID = "test"+ new Date().getTime();
        log.debug("runID = " + runID);
        this.principal = new X500Principal(NODE_OWNER);
        this.principal2 = new X500Principal(NODE_OWNER2);
        Set<Principal> pset = new HashSet<Principal>();
        Set<Principal> pset2 = new HashSet<Principal>();
        pset.add(principal);
        pset2.add(principal2);
        this.owner = new Subject(true,pset,new HashSet(), new HashSet());
        this.owner2 = new Subject(true,pset2,new HashSet(), new HashSet());

        try
        {
            DBConfig dbConfig = new DBConfig();
            ConnectionConfig connConfig = dbConfig.getConnectionConfig(SERVER, DATABASE);
            this.dataSource = DBUtil.getDataSource(connConfig);
            NodeSchema ns = new NodeSchema("Node", "NodeProperty", true, true); // TOP, writable
            this.nodeDAO = new NodeDAO(dataSource, ns, VOS_AUTHORITY, new X500IdentityManager());

            ContainerNode root = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("found base node: " + root);
            if (root == null)
            {
                VOSURI vos = new VOSURI(new URI("vos", VOS_AUTHORITY, "/"+HOME_CONTAINER, null, null));
                root = new ContainerNode(vos);
                root.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_CREATOR, NODE_OWNER));
                root = (ContainerNode) nodeDAO.put(root, owner);
                log.debug("created base node: " + root);
            }
        }
        catch(Exception ex)
        {
            // make sure it gets fully dumped
            log.error("SETUP FAILED", ex);
            throw ex;
        }
    }

    private String getNodeName(String s)
    {
        return runID + s;
    }

    private void assertRecursiveDelete()
        throws Exception
    {
        // ensure deleting the roots deleted all children
        PreparedStatement prepStmt = dataSource.getConnection().prepareStatement(
            "select count(*) from Node where name like ?");
        prepStmt.setString(1, runID + "%");
        ResultSet rs = prepStmt.executeQuery();
        rs.next();
        int remainingNodes = rs.getInt(1);
        Assert.assertEquals("recursive delete", 0, remainingNodes);
        prepStmt.close();
    }

    @Test
    public void testGetHome()
    {
        log.debug("testGetHome - START");
        try
        {
            Node root = nodeDAO.getPath(HOME_CONTAINER);
            Assert.assertNotNull(root);
            Assert.assertEquals(ContainerNode.class, root.getClass());
            Assert.assertEquals(HOME_CONTAINER, root.getName());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testGetHome - DONE");
        }
    }

    @Test
    public void testPutGetDeleteNodes()
    {
        log.debug("testPutGetDeleteNodes - START");
        try
        {
            DataNode dataNode = null;
            ContainerNode containerNode = null;
            Node putNode = null;

            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);
            String basePath = "/" + HOME_CONTAINER + "/";

            String nodePath2 = basePath + getNodeName("adir");
            containerNode = getCommonContainerNode(nodePath2, getCommonProperties());
            containerNode.setParent(rootContainer); // back link to persistent parent required
            putNode = nodeDAO.put(containerNode, owner);
            ContainerNode adir = (ContainerNode) nodeDAO.getPath(nodePath2);
            Assert.assertNotNull(adir);
            nodeDAO.getProperties(adir);
            log.debug("PutNode: " + putNode);
            log.debug("GetNode: " + adir);
            compareNodes("assert3", putNode, adir);
            compareProperties("assert4", putNode.getProperties(), adir.getProperties());

            // /adir/afile
            String nodePath4 = basePath + getNodeName("adir") + "/" + getNodeName("afile");
            dataNode = getCommonDataNode(nodePath4, getDataNodeProperties());
            dataNode.setParent(adir); // back link to persistent parent required
            putNode = nodeDAO.put(dataNode, owner);
            Node afile = nodeDAO.getPath(nodePath4);
            Assert.assertNotNull(afile);
            nodeDAO.getProperties(afile);
            compareNodes("assert7", putNode, afile);
            compareProperties("assert8", putNode.getProperties(), afile.getProperties());

            log.debug("testPutGetDeleteNodes - CLEANUP");

            // delete the three roots
            nodeDAO.delete(adir);

            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testPutGetDeleteNodes - DONE");
        }
    }

    @Test
    public void testGetChildren()
    {
        log.debug("testGetChildren - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // create a container
            String path = basePath + getNodeName("dir");
            ContainerNode testNode = getCommonContainerNode(path);
            testNode.setParent(rootContainer);
            ContainerNode cn = (ContainerNode) nodeDAO.put(testNode, owner);
            
            ContainerNode cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);

            DataNode n1 = getCommonDataNode(path + "/one");
            ContainerNode n2 = getCommonContainerNode(path + "/two");
            DataNode n3 = getCommonDataNode(path + "/three");
            ContainerNode n4 = getCommonContainerNode(path + "/four");

            n1.setParent(cn);
            n2.setParent(cn);
            n3.setParent(cn);
            n4.setParent(cn);
            nodeDAO.put(n1, owner);
            nodeDAO.put(n2, owner);
            nodeDAO.put(n3, owner);
            nodeDAO.put(n4, owner);

            // get a vanilla container with no children
            cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);
            Assert.assertEquals("empty child list", 0, cur.getNodes().size());
            // load the child nodes
            nodeDAO.getChildren(cur);
            Assert.assertEquals("full child list", 4, cur.getNodes().size());
            // rely on implementation of Node.equals
            Assert.assertTrue(cur.getNodes().contains(n1));
            Assert.assertTrue(cur.getNodes().contains(n2));
            Assert.assertTrue(cur.getNodes().contains(n3));
            Assert.assertTrue(cur.getNodes().contains(n4));

            nodeDAO.delete(cur);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testGetChildren - DONE");
        }
    }

    @Test
    public void testGetChildrenLimit()
    {
        log.debug("testGetChildren - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // create a container
            String path = basePath + getNodeName("dir");
            ContainerNode testNode = getCommonContainerNode(path);
            testNode.setParent(rootContainer);
            ContainerNode cn = (ContainerNode) nodeDAO.put(testNode, owner);

            ContainerNode cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);

            // make 4 nodes in predictable alpha-order == NodeDAO ordering
            DataNode n1 = getCommonDataNode(path + "/abc");
            ContainerNode n2 = getCommonContainerNode(path + "/bcd");
            DataNode n3 = getCommonDataNode(path + "/cde");
            ContainerNode n4 = getCommonContainerNode(path + "/def");

            n1.setParent(cn);
            n2.setParent(cn);
            n3.setParent(cn);
            n4.setParent(cn);
            nodeDAO.put(n1, owner);
            nodeDAO.put(n2, owner);
            nodeDAO.put(n3, owner);
            nodeDAO.put(n4, owner);

            // get a vanilla container with no children
            cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);
            Assert.assertEquals("empty child list", 0, cur.getNodes().size());
            // load 2 child nodes
            nodeDAO.getChildren(cur, null, new Integer(2));
            Assert.assertEquals("leading partial child list", 2, cur.getNodes().size());
            // rely on implementation of Node.equals
            Assert.assertTrue(cur.getNodes().contains(n1));
            Assert.assertTrue(cur.getNodes().contains(n2));

            // get a trailing batch
            cur.getNodes().clear();
            nodeDAO.getChildren(cur, n3.getUri(), new Integer(100));
            Assert.assertEquals("trailing partial child list", 2, cur.getNodes().size());
            Assert.assertTrue(cur.getNodes().contains(n3));
            Assert.assertTrue(cur.getNodes().contains(n4));

            nodeDAO.delete(cur);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testGetChildren - DONE");
        }
    }

    @Test
    public void testGetChild()
    {
        log.debug("testGetChild - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // create a container
            String path = basePath + getNodeName("dir");
            ContainerNode testNode = getCommonContainerNode(path);
            testNode.setParent(rootContainer);
            ContainerNode cn = (ContainerNode) nodeDAO.put(testNode, owner);

            ContainerNode cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);

            DataNode n1 = getCommonDataNode(path + "/one");
            ContainerNode n2 = getCommonContainerNode(path + "/two");
            DataNode n3 = getCommonDataNode(path + "/three");
            ContainerNode n4 = getCommonContainerNode(path + "/four");

            n1.setParent(cn);
            n2.setParent(cn);
            n3.setParent(cn);
            n4.setParent(cn);
            nodeDAO.put(n1, owner);
            nodeDAO.put(n2, owner);
            nodeDAO.put(n3, owner);
            nodeDAO.put(n4, owner);

            // get a vanilla container with no children
            cur = (ContainerNode) nodeDAO.getPath(path);
            Assert.assertNotNull(cur);
            Assert.assertEquals("empty child list", 0, cur.getNodes().size());
            // load the child nodes one at a time
            nodeDAO.getChild(cur, n1.getName());
            Assert.assertEquals("contains 1", 1, cur.getNodes().size());
            Assert.assertTrue("contains n1", cur.getNodes().contains(n1));
            
             nodeDAO.getChild(cur, n4.getName());
            Assert.assertEquals("contains 2", 2, cur.getNodes().size());
            Assert.assertTrue("contains n4", cur.getNodes().contains(n4));

             nodeDAO.getChild(cur, n2.getName());
            Assert.assertEquals("contains 3", 3, cur.getNodes().size());
            Assert.assertTrue("contains n2", cur.getNodes().contains(n2));

             nodeDAO.getChild(cur, n3.getName());
            Assert.assertEquals("contains 4", 4, cur.getNodes().size());
            Assert.assertTrue("contains n3", cur.getNodes().contains(n3));

            nodeDAO.delete(cur);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testGetChild - DONE");
        }
    }


    @Test
    public void testUpdateProperties()
    {
        log.debug("testUpdateProperties - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // Create a node with properties
            String path = basePath + getNodeName("g");
            DataNode testNode = getCommonDataNode(path);
            testNode.getProperties().add(new NodeProperty("uri1", "value1"));
            testNode.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_CONTENTLENGTH, new Long(1024).toString()));
            testNode.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_TYPE, "text/plain"));
            testNode.setParent(rootContainer);

            // put + get + compare
            nodeDAO.put(testNode, owner);
            DataNode nodeFromGet = (DataNode) nodeDAO.getPath(path);
            Assert.assertNotNull(nodeFromGet);
            nodeDAO.getProperties(nodeFromGet);
            compareProperties("assert1", testNode.getProperties(), nodeFromGet.getProperties());

            // add
            List<NodeProperty> props = new ArrayList<NodeProperty>();
            props.add(new NodeProperty("uri2", "value1"));
            props.add(new NodeProperty(VOS.PROPERTY_URI_CONTENTENCODING, "gzip"));
            props.add(new NodeProperty(VOS.PROPERTY_URI_CONTENTMD5, HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})));
            testNode.getProperties().addAll(props); // for comparison below

            DataNode nodeFromUpdate1 = (DataNode) nodeDAO.updateProperties(nodeFromGet, props);
            Assert.assertNotNull(nodeFromUpdate1);
            compareProperties("assert2", testNode.getProperties(), nodeFromUpdate1.getProperties());

            DataNode reGet1 = (DataNode) nodeDAO.getPath(path);
            nodeDAO.getProperties(reGet1);
            Assert.assertNotNull(reGet1);
            compareProperties("assert3", testNode.getProperties(), reGet1.getProperties());

            // replace values
            testNode.getProperties().remove(new NodeProperty("uri1", null));
            testNode.getProperties().add(new NodeProperty("uri1", "value2"));
            testNode.getProperties().remove(new NodeProperty(VOS.PROPERTY_URI_CONTENTLENGTH, null));
            testNode.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_CONTENTLENGTH, new Long(2048).toString()));
            testNode.getProperties().remove(new NodeProperty(VOS.PROPERTY_URI_TYPE, null));
            testNode.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_TYPE, "application/pdf"));

            DataNode nodeFromUpdate2 = (DataNode) nodeDAO.updateProperties(nodeFromUpdate1, testNode.getProperties());
            Assert.assertNotNull(nodeFromUpdate2);
            compareProperties("assert4", testNode.getProperties(), nodeFromUpdate2.getProperties());

            DataNode reGet2 = (DataNode) nodeDAO.getPath(path);
            nodeDAO.getProperties(reGet2);
            Assert.assertNotNull(reGet2);
            compareProperties("assert5", testNode.getProperties(), nodeFromUpdate2.getProperties());


            // remove
            props = new ArrayList<NodeProperty>();
            NodeProperty newURI2 = new NodeProperty("uri2", "value1");
            newURI2.setMarkedForDeletion(true);
            props.add(newURI2);
            NodeProperty newEncoding = new NodeProperty(VOS.PROPERTY_URI_CONTENTENCODING, "gzip");
            newEncoding.setMarkedForDeletion(true);
            props.add(newEncoding);
            NodeProperty newMD5 = new NodeProperty(VOS.PROPERTY_URI_CONTENTMD5, HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
            newMD5.setMarkedForDeletion(true);
            props.add(newMD5);

            testNode.getProperties().removeAll(props); // remove from client side

            DataNode nodeFromUpdate3 = (DataNode) nodeDAO.updateProperties(nodeFromUpdate2, props); // remove from server
            Assert.assertNotNull(nodeFromUpdate3);
            compareProperties("assert6", testNode.getProperties(), nodeFromUpdate3.getProperties());

            DataNode reGet3 = (DataNode) nodeDAO.getPath(path);
            nodeDAO.getProperties(reGet3);
            Assert.assertNotNull(reGet3);
            compareProperties("assert7", testNode.getProperties(), reGet3.getProperties());

            nodeDAO.delete(nodeFromGet);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testUpdateProperties - DONE");
        }
    }

    @Test
    public void testSetBusyState()
    {
        log.debug("testSetBusyState - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // Create a node with properties
            String path = basePath + getNodeName("cl-test");
            DataNode testNode = getCommonDataNode(path);
            testNode.setParent(rootContainer);

            // put and check default
            nodeDAO.put(testNode, owner);
            DataNode persistNode = (DataNode) nodeDAO.getPath(path);
            Assert.assertNotNull(persistNode);
            Assert.assertEquals("assert not busy", NodeBusyState.notBusy, persistNode.getBusy());

            // -> write
            nodeDAO.setBusyState(persistNode, NodeBusyState.notBusy, NodeBusyState.busyWithWrite);
            persistNode = (DataNode) nodeDAO.getPath(path);
            Assert.assertNotNull(persistNode);
            Assert.assertEquals("assert not busy", NodeBusyState.busyWithWrite, persistNode.getBusy());

            // -> not busy
            nodeDAO.setBusyState(persistNode, NodeBusyState.busyWithWrite, NodeBusyState.notBusy);
            persistNode = (DataNode) nodeDAO.getPath(path);
            Assert.assertNotNull(persistNode);
            Assert.assertEquals("assert not busy", NodeBusyState.notBusy, persistNode.getBusy());

            nodeDAO.delete(persistNode);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testSetBusyState - DONE");
        }
    }

    @Test
    public void testUpdateFileMetadata()
    {
        log.debug("testUpdateFileMetadata - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // Create a node with properties
            String path = basePath + getNodeName("ufm-test");
            DataNode testNode = getCommonDataNode(path);
            testNode.setParent(rootContainer);
            nodeDAO.put(testNode, owner);
            DataNode persistNode = (DataNode) nodeDAO.getPath(path);
            Assert.assertNotNull(persistNode);

            // update the quick way
            FileMetadata meta = new FileMetadata();
            meta.setContentLength(new Long(2048L));
            meta.setContentEncoding("gzip");
            meta.setContentType("text/plain");
            meta.setMd5Sum(HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));

            try
            {
                nodeDAO.updateNodeMetadata(persistNode, meta);
                Assert.fail("expected IllegalStateException calling updateNodeMetadata with busy=N");
            }
            catch(IllegalStateException expected)
            {
                log.debug("caught expected exception: " + expected);
            }

            // set busy state correctly and redo
            nodeDAO.setBusyState(persistNode, NodeBusyState.notBusy, NodeBusyState.busyWithWrite);

            nodeDAO.updateNodeMetadata(persistNode, meta);

            Node nodeFromGet2 = nodeDAO.getPath(path);
            Assert.assertNotNull(nodeFromGet2);
            Assert.assertEquals("assert2048", 2048, getContentLength(nodeFromGet2));
            NodeProperty np;
            
            np = nodeFromGet2.findProperty(VOS.PROPERTY_URI_CONTENTLENGTH);
            Assert.assertNotNull("contentLength NP", np);
            Assert.assertEquals(meta.getContentLength().longValue(), Long.parseLong(np.getPropertyValue()));
            
            np = nodeFromGet2.findProperty(VOS.PROPERTY_URI_TYPE);
            Assert.assertNotNull("contentType NP", np);
            Assert.assertEquals(meta.getContentType(), np.getPropertyValue());
            
            np = nodeFromGet2.findProperty(VOS.PROPERTY_URI_CONTENTENCODING);
            Assert.assertNotNull("contentEncoding NP", np);
            Assert.assertEquals(meta.getContentEncoding(), np.getPropertyValue());
            
            np = nodeFromGet2.findProperty(VOS.PROPERTY_URI_CONTENTMD5);
            Assert.assertNotNull("contentMD5 NP", np);
            Assert.assertEquals(meta.getMd5Sum(), np.getPropertyValue());

            nodeDAO.delete(persistNode);
            assertRecursiveDelete();
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testUpdateFileMetadata - DONE");
        }
    }

    

    @Test
    public void testGetRoot()
    {
        log.debug("testGetRoot - START");
        try
        {

            VOSURI vos = new VOSURI(new URI("vos", VOS_AUTHORITY, null, null, null));
            log.debug("path with null: [" + vos.getPath() + "]");
            ContainerNode root = new ContainerNode(vos);

            vos = new VOSURI(new URI("vos", VOS_AUTHORITY, "", null, null));
            log.debug("path with 0-length string: [" + vos.getPath() + "]");
            root = new ContainerNode(vos);

            root.appData = new NodeID(); // null internal ID means root
            root.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_ISPUBLIC, "true"));
            nodeDAO.getChildren(root);
            for (Node n : root.getNodes())
                log.debug("found: " + n);

        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testGetRoot - DONE");
        }
    }
    
    @Test
    public void testMove()
    {
        log.debug("testMove - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // Create a new node tree
            String moveRootPath = basePath + getNodeName("movetest");
            String moveCont1Path = moveRootPath + "/" + getNodeName("movecont1");
            String moveCont2Path = moveRootPath + "/" + getNodeName("movecont2");
            String moveData1Path = moveRootPath + "/" + getNodeName("movedata1");
            String moveCont3Path = moveCont1Path + "/" + getNodeName("movecont3");
            String moveData2Path = moveCont1Path + "/" + getNodeName("movedata2");
            String moveData3Path = moveCont2Path + "/" + getNodeName("movedata3");
            String moveData4Path = moveCont3Path + "/" + getNodeName("movedata4");
            
            ContainerNode moveRoot = getCommonContainerNode(moveRootPath);
            ContainerNode moveCont1 = getCommonContainerNode(moveCont1Path);
            ContainerNode moveCont2 = getCommonContainerNode(moveCont2Path);
            DataNode moveData1 = getCommonDataNode(moveData1Path);
            ContainerNode moveCont3 = getCommonContainerNode(moveCont3Path);
            DataNode moveData2 = getCommonDataNode(moveData2Path);
            DataNode moveData3 = getCommonDataNode(moveData3Path);
            DataNode moveData4 = getCommonDataNode(moveData4Path);
            
            moveRoot.setParent(rootContainer);
            moveRoot = (ContainerNode) nodeDAO.put(moveRoot, owner);
            moveCont1.setParent(moveRoot);
            moveCont1 = (ContainerNode) nodeDAO.put(moveCont1, owner);
            moveCont2.setParent(moveRoot);
            moveCont2 = (ContainerNode) nodeDAO.put(moveCont2, owner);
            moveData1.setParent(moveRoot);
            moveData1 = (DataNode) nodeDAO.put(moveData1, owner);
            moveCont3.setParent(moveCont1);
            moveCont3 = (ContainerNode) nodeDAO.put(moveCont3, owner);
            moveData2.setParent(moveCont1);
            moveData2 = (DataNode) nodeDAO.put(moveData2, owner);
            moveData3.setParent(moveCont2);
            moveData3 = (DataNode) nodeDAO.put(moveData3, owner);
            moveData4.setParent(moveCont3);
            moveData4 = (DataNode) nodeDAO.put(moveData4, owner);
            
            // move cont2 to cont3
            nodeDAO.move(moveCont2, moveCont3, owner);
            
            // check that cont2 no longer under moveRoot
            moveRoot = (ContainerNode) nodeDAO.getPath(moveRootPath);
            Assert.assertNotNull(moveRoot);
            nodeDAO.getChildren(moveRoot);
            for (Node child : moveRoot.getNodes())
            {
                if (child.getName().equals(moveCont2.getName()) ||
                        ((NodeID) child.appData).equals(((NodeID) moveCont2.appData).getID()))
                {
                    Assert.fail("Failed to move container 2: still in old location.");
                }
            }
            
            // check that cont2 under cont3
            moveCont3 = (ContainerNode) nodeDAO.getPath(moveCont3Path);
            Assert.assertNotNull(moveCont3);
            nodeDAO.getChildren(moveCont3);
            boolean found = false;
            for (Node child : moveCont3.getNodes())
            {
                if (child.getName().equals(moveCont2.getName()) &&
                        ((NodeID) child.appData).getID().equals(((NodeID) moveCont2.appData).getID()))
                {
                    found = true;
                }
            }
            if (!found)
                Assert.fail("Failed to move container 2: not in new location.");
            
            // check that cont2 has parent cont3 and child data3
            moveCont2 = (ContainerNode) nodeDAO.getPath(moveCont3Path + "/" + moveCont2.getName());
            Assert.assertNotNull(moveCont2);
            nodeDAO.getChildren(moveCont2);
            assertEquals("Cont2 has wrong parent.", moveCont3.getName(), moveCont2.getParent().getName());
            assertEquals("Cont2 has wrong parent.", ((NodeID) moveCont3.appData).getID(), ((NodeID) moveCont2.getParent().appData).getID());
            found = false;
            for (Node child : moveCont2.getNodes())
            {
                if (child.getName().equals(moveData3.getName()) &&
                        ((NodeID) child.appData).getID().equals(((NodeID) moveData3.appData).getID()))
                {
                    found = true;
                }
            }
            if (!found)
                Assert.fail("Lost child movedata4 on move.");
            
            // move to a container underneath own tree (not allowed)
            moveCont1 = (ContainerNode) nodeDAO.getPath(moveCont1Path);
            Assert.assertNotNull(moveCont1);
            moveCont2 = (ContainerNode) nodeDAO.getPath(moveCont3Path + "/" + moveCont2.getName());
            Assert.assertNotNull(moveCont2);
            try
            {
                nodeDAO.move(moveCont1, moveCont2, owner);
                Assert.fail("Move should not have been allowed due to circular tree.");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            
            // try to move root (not allowed)
            try
            {
                Node root = new ContainerNode(new VOSURI("vos://cadc.nrc.ca~vospace/"));
                nodeDAO.move(root, moveCont1, owner);
                Assert.fail("Should not have been allowed move root.");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            
            // try to move root container (not allowed)
            try
            {
                nodeDAO.move(rootContainer, moveCont1, owner);
                Assert.fail("Should not have been allowed move root container.");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
            
            // move with new owner, new name
            moveCont1 = (ContainerNode) nodeDAO.getPath(moveCont1Path);
            moveData3 = (DataNode) nodeDAO.getPath(moveCont3Path + "/" + moveCont2.getName() + "/" + moveData3.getName());
            String newName = getNodeName("newName");
            moveData3.setName(newName);
            nodeDAO.move(moveData3, moveCont1, owner2);
            
            // check that moveRoot now has moveData3
            moveCont1 = (ContainerNode) nodeDAO.getPath(moveCont1Path);
            nodeDAO.getChildren(moveCont1);
            found = false;
            for (Node child : moveCont1.getNodes())
            {
                String childOwner = child.getPropertyValue(VOS.PROPERTY_URI_CREATOR);
                if (child.getName().equals(newName) &&
                        (childOwner.equalsIgnoreCase(NODE_OWNER2)) &&
                        ((NodeID) child.appData).getID().equals(((NodeID) moveData3.appData).getID()))
                {
                    found = true;
                }
            }
            if (!found)
                Assert.fail("moveData4 not under root after move (owner, id, name checked.)");
            
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testMove - DONE");
        }
    }
    
    @Test
    public void testChown()
    {
        log.debug("testChown - START");
        try
        {
            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);

            String basePath = "/" + HOME_CONTAINER + "/";

            // Create a new node tree with owner/creator NODE_OWNER
            String chownRootPath = basePath + getNodeName("chowntest");
            String chownSub1Path = chownRootPath + "/" + getNodeName("chownsub1");
            String chownSub2Path = chownRootPath + "/" + getNodeName("chownsub2");
            String chownSub3Path = chownRootPath + "/" + getNodeName("chownsub3");
            String chownSub1Sub1Path = chownSub1Path + "/" + getNodeName("chownsub1sub1");
            String chownSub1Sub2Path = chownSub1Path + "/" + getNodeName("chownsub1sub2");
            String chownSub2Sub1Path = chownSub2Path + "/" + getNodeName("chownsub2sub1");
            String chownSub1Sub1Sub1Path = chownSub1Sub1Path + "/" + getNodeName("chownsub1sub1sub1");
            
            ContainerNode chownRoot = getCommonContainerNode(chownRootPath);
            ContainerNode chownSub1 = getCommonContainerNode(chownSub1Path);
            ContainerNode chownSub2 = getCommonContainerNode(chownSub2Path);
            DataNode chownSub3 = getCommonDataNode(chownSub3Path);
            ContainerNode chownSub1Sub1 = getCommonContainerNode(chownSub1Sub1Path);
            DataNode chownSub1Sub2 = getCommonDataNode(chownSub1Sub2Path);
            DataNode chownSub2Sub1 = getCommonDataNode(chownSub2Sub1Path);
            DataNode chownSub1Sub1Sub1 = getCommonDataNode(chownSub1Sub1Sub1Path);
            
            chownRoot.setParent(rootContainer);
            chownRoot = (ContainerNode) nodeDAO.put(chownRoot, owner);
            chownSub1.setParent(chownRoot);
            chownSub1 = (ContainerNode) nodeDAO.put(chownSub1, owner);
            chownSub2.setParent(chownRoot);
            chownSub2 = (ContainerNode) nodeDAO.put(chownSub2, owner);
            chownSub3.setParent(chownRoot);
            chownSub3 = (DataNode) nodeDAO.put(chownSub3, owner);
            chownSub1Sub1.setParent(chownSub1);
            chownSub1Sub1 = (ContainerNode) nodeDAO.put(chownSub1Sub1, owner);
            chownSub1Sub2.setParent(chownSub1);
            chownSub1Sub2 = (DataNode) nodeDAO.put(chownSub1Sub2, owner);
            chownSub2Sub1.setParent(chownSub2);
            chownSub2Sub1 = (DataNode) nodeDAO.put(chownSub2Sub1, owner);
            chownSub1Sub1Sub1.setParent(chownSub1Sub1);
            chownSub1Sub1Sub1 = (DataNode) nodeDAO.put(chownSub1Sub1Sub1, owner);
            
            // get the root node
            chownRoot = (ContainerNode) nodeDAO.getPath(chownRootPath);
            Assert.assertNotNull(chownRoot);

            // change the ownership non recursively
            nodeDAO.chown(chownRoot, owner2, false);
            
            // check the ownership change
            chownRoot = (ContainerNode) nodeDAO.getPath(chownRootPath);
            assertEquals("Non-recursive chown failed.",
                    chownRoot.getPropertyValue(VOS.PROPERTY_URI_CREATOR).toLowerCase(),
                    NODE_OWNER2.toLowerCase());
            
            // get a sub node
            chownSub1 = (ContainerNode) nodeDAO.getPath(chownSub1Path);
            
            // check for no ownership change
            assertEquals("Non-recursive chown failed.",
                    chownSub1.getPropertyValue(VOS.PROPERTY_URI_CREATOR).toLowerCase(),
                    NODE_OWNER.toLowerCase());
            
            // change the ownership recursively
            nodeDAO.chown(chownRoot, owner2, true);
            
            // check for deep ownership change
            chownSub1Sub1Sub1 = (DataNode) nodeDAO.getPath(chownSub1Sub1Sub1Path);
            
            assertEquals("Recursive chown failed.",
                    chownSub1Sub1Sub1.getPropertyValue(VOS.PROPERTY_URI_CREATOR).toLowerCase(),
                    NODE_OWNER2.toLowerCase());
            
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testChown - DONE");
        }
    }

    @Test
    public void testMD5()
    {
        // md5 is stored as a binary(16) which is sometimes tricky with trailing zero(s)
        log.debug("testMD5 - START");
        try
        {
            DataNode dataNode = null;
            ContainerNode containerNode = null;
            Node putNode = null;

            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);
            String basePath = "/" + HOME_CONTAINER + "/";

            NodeProperty md5 = new NodeProperty(VOS.PROPERTY_URI_CONTENTMD5, HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 0}));
            log.debug("md5: " + md5.getPropertyValue());
            // /a
            String nodePath1 = basePath + getNodeName("a");
            List<NodeProperty> props = new ArrayList<NodeProperty>();
            props.add(md5);
            dataNode = getCommonDataNode(nodePath1, props);
            dataNode.setParent(rootContainer); // back link to persistent parent required
            putNode = nodeDAO.put(dataNode, owner);
            Node nodeA = nodeDAO.getPath(nodePath1);
            Assert.assertNotNull(nodeA);
            nodeDAO.getProperties(nodeA);
            log.debug("PutNode: " + putNode);
            log.debug("GetNode: " + nodeA);
            compareNodes("assert1", putNode, nodeA);
            compareProperties("assert2a", dataNode.getProperties(), putNode.getProperties());
            compareProperties("assert2b", putNode.getProperties(), nodeA.getProperties());
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testMD5 - DONE");
        }
    }

    @Test
    public void testReadOnlyFileMetadata()
    {
        // md5 is stored as a binary(16) which is sometimes tricky with trailing zero(s)
        log.debug("testReadOnlyFileMetadata - START");
        try
        {
            DBConfig dbConfig = new DBConfig();
            ConnectionConfig connConfig = dbConfig.getConnectionConfig(SERVER, DATABASE);
            this.dataSource = DBUtil.getDataSource(connConfig);
            NodeSchema ns = new NodeSchema("Node", "NodeProperty", true, false); // TOP, read-only
            this.nodeDAO = new NodeDAO(dataSource, ns, VOS_AUTHORITY, new X500IdentityManager());
            
            DataNode dataNode = null;
            ContainerNode containerNode = null;
            Node putNode = null;

            ContainerNode rootContainer = (ContainerNode) nodeDAO.getPath(HOME_CONTAINER);
            log.debug("ROOT: " + rootContainer);
            Assert.assertNotNull(rootContainer);
            String basePath = "/" + HOME_CONTAINER + "/";

            NodeProperty len = new NodeProperty(VOS.PROPERTY_URI_CONTENTLENGTH, "123");
            NodeProperty md5 = new NodeProperty(VOS.PROPERTY_URI_CONTENTMD5, HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 0}));
            log.debug("len: " + len.getPropertyValue());
            log.debug("md5: " + md5.getPropertyValue());
            // /a
            String nodePath1 = basePath + getNodeName("a");
            List<NodeProperty> props = new ArrayList<NodeProperty>();
            props.add(len);
            props.add(md5);
            dataNode = getCommonDataNode(nodePath1, props);
            dataNode.setParent(rootContainer); // back link to persistent parent required
            putNode = nodeDAO.put(dataNode, owner);
            Node nodeA = nodeDAO.getPath(nodePath1);
            Assert.assertNotNull(nodeA);
            nodeDAO.getProperties(nodeA);
            log.debug("PutNode: " + putNode);
            log.debug("GetNode: " + nodeA);
            
            // we tried to set the props, but they are not writable
            NodeProperty lenActual = nodeA.findProperty(VOS.PROPERTY_URI_CONTENTLENGTH);
            NodeProperty md5Actual = nodeA.findProperty(VOS.PROPERTY_URI_CONTENTMD5);
            Assert.assertNull("persisted contentLength", lenActual);
            Assert.assertNull("persisted contentMD5", lenActual);
        }
        catch(Exception unexpected)
        {
            log.error("unexpected exception", unexpected);
            Assert.fail("unexpected exception: " + unexpected);
        }
        finally
        {
            log.debug("testReadOnlyFileMetadata - DONE");
        }
    }



    private long getContentLength(Node node)
    {
        String str = node.getPropertyValue(VOS.PROPERTY_URI_CONTENTLENGTH);
        if (str != null)
            return Long.parseLong(str);
        return 0;
    }
    
    private DataNode getCommonDataNode(String path, List<NodeProperty> properties) throws Exception
    {
        DataNode dataNode = getCommonDataNode(path);
        dataNode.getProperties().addAll(properties);
        return dataNode;
    }
    
    private DataNode getCommonDataNode(String path) throws Exception
    {
        VOSURI vosuri = new VOSURI(new URI("vos", VOS_AUTHORITY, path, null, null));
        DataNode dataNode = new DataNode(vosuri);
        //dataNode.getProperties().add(new NodeProperty(VOS.PROPERTY_URI_CREATOR, NODE_OWNER));
        return dataNode;
    }
    
    private ContainerNode getCommonContainerNode(String path, List<NodeProperty> properties) throws Exception
    {
        ContainerNode containerNode = getCommonContainerNode(path);
        containerNode.getProperties().addAll(properties);
        return containerNode;
    }
    
    private ContainerNode getCommonContainerNode(String path) throws Exception
    {
        VOSURI vosuri = new VOSURI(new URI("vos", VOS_AUTHORITY, path, null, null));
        ContainerNode containerNode = new ContainerNode(vosuri);
        return containerNode;
    }

    private List<NodeProperty> getCommonProperties()
    {
        List<NodeProperty> properties = new ArrayList<NodeProperty>();
        NodeProperty prop1 = new NodeProperty("uri1", "value1");
        NodeProperty prop2 = new NodeProperty("uri2", "value2");

        properties.add(prop1);
        properties.add(prop2);

        return properties;
    }
    private List<NodeProperty> getDataNodeProperties()
    {
        List<NodeProperty> properties = getCommonProperties();
        NodeProperty prop3 = new NodeProperty(VOS.PROPERTY_URI_CONTENTLENGTH, new Long(1024).toString());
        NodeProperty prop4 = new NodeProperty(VOS.PROPERTY_URI_TYPE, "text/plain");
        NodeProperty prop5 = new NodeProperty(VOS.PROPERTY_URI_CONTENTENCODING, "gzip");
        NodeProperty prop6 = new NodeProperty(VOS.PROPERTY_URI_CONTENTMD5, HexUtil.toHex(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));

        properties.add(prop3);
        properties.add(prop4);
        properties.add(prop5);
        properties.add(prop6);

        return properties;
    }

    private void compareNodes(String assertName, Node a, Node b)
    {
        Assert.assertNotNull(b);
        Assert.assertEquals(assertName+  "URI", a.getUri(), b.getUri());
        Assert.assertEquals(assertName + "type", a.getClass().getName(), b.getClass().getName());
        Assert.assertEquals(assertName + "name", a.getName(), b.getName());
        Subject subject = ((NodeID)b.appData).getOwner();
        Assert.assertNotNull(assertName+  " owner", owner);
        Principal xp = null;
        for (Principal principal : subject.getPrincipals())
        {
            if (principal instanceof X500Principal)
            {
                xp = principal;
                break;
            }
        }
        Assert.assertNotNull(xp);
        Assert.assertTrue("caller==owner", AuthenticationUtil.equals(principal, xp));
    }

    private void compareProperties(String assertName, List<NodeProperty> expected, List<NodeProperty> actual)
    {
        for (NodeProperty np : expected)
            log.debug(assertName+".expected: " + np);
        for (NodeProperty np : actual)
            log.debug(assertName+".actual: " + np);
        boolean match = true;
        for (NodeProperty e : expected)
        {
            boolean found = false;
            for (NodeProperty a : actual)
            {
                if ( e.getPropertyURI().equals(a.getPropertyURI()))
                {
                    if ( isDN(e.getPropertyURI()) )
                        Assert.assertTrue(
                                AuthenticationUtil.equals(
                                    new X500Principal(e.getPropertyValue()),
                                    new X500Principal(a.getPropertyValue()
                                    )
                                ));
                    else if ( isDate(e.getPropertyURI()))
                        // TODO: some sort of sensible comparison?
                        Assert.assertNotNull("date prop", a.getPropertyValue());
                    else
                        Assert.assertEquals(e.getPropertyURI(), e.getPropertyValue(), a.getPropertyValue());
                    found = true;
                }
            }
            Assert.assertTrue("found "+e.getPropertyURI(), found);
        }
    }

    private boolean isDate(String uri)
    {
        if ( VOS.PROPERTY_URI_DATE.equals(uri))
            return true;
        return false;
    }

    private boolean isDN(String uri)
    {
        if ( VOS.PROPERTY_URI_CREATOR.equals(uri))
            return true;
        return false;
    }
}

