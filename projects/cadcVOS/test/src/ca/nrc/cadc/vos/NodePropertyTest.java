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

package ca.nrc.cadc.vos;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class NodePropertyTest
{

    @Test
    public void testMultipleGroupReadValues()
    {
        List<String> values = new ArrayList<String>();
        values.add("val1");
        values.add("val2");
        values.add("val3");
        String stringValues = NodeProperty.serializePropertyValueList(
                VOS.PROPERTY_URI_GROUPREAD, values);
        String expected = "val1" + VOS.PROPERTY_DELIM_GROUPREAD + "val2"
                + VOS.PROPERTY_DELIM_GROUPREAD + "val3";
        Assert.assertEquals("bad serialization", expected, stringValues);
        List<String> extracted = new NodeProperty(VOS.PROPERTY_URI_GROUPREAD, stringValues).extractPropertyValueList();
        Assert.assertArrayEquals("bad extraction",
                values.toArray(new String[0]), extracted.toArray(new String[0]));

        NodeProperty prop = new NodeProperty(VOS.PROPERTY_URI_GROUPREAD, values);
        Assert.assertEquals("bad constructor", expected,
                prop.getPropertyValue());

        try
        {
            values.clear();
            for (int i = 0; i <= NodeProperty.MAX_GROUPS; i++)
            {
                values.add("val" + i);
            }
            new NodeProperty(VOS.PROPERTY_URI_GROUPREAD, values);
            Assert.fail("Should have received illegal argument for too many property values.");
        } catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i <= NodeProperty.MAX_GROUPS; i++)
            {
                sb.append("val" + i);
                if (i < NodeProperty.MAX_GROUPS)
                    sb.append(VOS.PROPERTY_DELIM_GROUPREAD);
            }
            new NodeProperty(VOS.PROPERTY_URI_GROUPREAD, sb.toString());
            Assert.fail("Should have received illegal argument for too many property values.");
        } catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    @Test
    public void testMultipleGroupWriteValues()
    {
        List<String> values = new ArrayList<String>();
        values.add("val1");
        values.add("val2");
        values.add("val3");
        String stringValues = NodeProperty.serializePropertyValueList(
                VOS.PROPERTY_URI_GROUPWRITE, values);
        String expected = "val1" + VOS.PROPERTY_DELIM_GROUPWRITE + "val2"
                + VOS.PROPERTY_DELIM_GROUPWRITE + "val3";
        Assert.assertEquals("bad serialization", expected, stringValues);
        List<String> extracted = new NodeProperty(VOS.PROPERTY_URI_GROUPWRITE, stringValues).extractPropertyValueList();
        Assert.assertArrayEquals("bad extraction",
                values.toArray(new String[0]), extracted.toArray(new String[0]));

        NodeProperty prop = new NodeProperty(VOS.PROPERTY_URI_GROUPWRITE,
                values);
        Assert.assertEquals("bad constructor", expected,
                prop.getPropertyValue());

        try
        {
            values.clear();
            for (int i = 0; i <= NodeProperty.MAX_GROUPS; i++)
            {
                values.add("val" + i);
            }
            new NodeProperty(VOS.PROPERTY_URI_GROUPWRITE, values);
            Assert.fail("Should have received illegal argument for too many property values.");
        } catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i <= NodeProperty.MAX_GROUPS; i++)
            {
                sb.append("val" + i);
                if (i < NodeProperty.MAX_GROUPS)
                    sb.append(VOS.PROPERTY_DELIM_GROUPWRITE);
            }
            new NodeProperty(VOS.PROPERTY_URI_GROUPWRITE, sb.toString());
            Assert.fail("Should have received illegal argument for too many property values.");
        } catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    @Test
    public void testIsPublicValues()
    {

        try
        {
            List<String> values = new ArrayList<String>();
            values.add("true");
            values.add("true");
            new NodeProperty(VOS.PROPERTY_URI_ISPUBLIC, values);
            Assert.fail("Should have received illegal argument for too many property values.");
        } catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    @Test
    public void testMultipleDefaultPropertyValues()
    {
        List<String> values = new ArrayList<String>();
        values.add("val1");
        values.add("val2");
        values.add("val3");
        String stringValues = NodeProperty.serializePropertyValueList(
                VOS.PROPERTY_URI_CONTRIBUTOR, values);
        String expected = "val1" + VOS.DEFAULT_PROPERTY_VALUE_DELIM + "val2"
                + VOS.DEFAULT_PROPERTY_VALUE_DELIM + "val3";
        Assert.assertEquals("bad serialization", expected, stringValues);
        List<String> extracted = new NodeProperty(VOS.PROPERTY_URI_CONTRIBUTOR, stringValues).extractPropertyValueList();
        Assert.assertArrayEquals("bad extraction",
                values.toArray(new String[0]), extracted.toArray(new String[0]));

        NodeProperty prop = new NodeProperty(VOS.PROPERTY_URI_CONTRIBUTOR,
                values);
        Assert.assertEquals("bad constructor", expected,
                prop.getPropertyValue());
    }

    @Test
    public void testParseMatchingExpression()
    {
        try
        {
            NodeProperty.parseMatchingExpression(null);
            Assert.fail("Should be an illegal argument.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            NodeProperty.parseMatchingExpression("");
            Assert.fail("Should be an illegal argument.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            // no equals sign
            NodeProperty.parseMatchingExpression("keyvalue");
            Assert.fail("Should be an illegal argument.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            // too many equals signs
            NodeProperty.parseMatchingExpression("key=value=value");
            Assert.fail("Should be an illegal argument.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            // adjacent equals signs
            NodeProperty.parseMatchingExpression("key==value");
            Assert.fail("Should be an illegal argument.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        NodeProperty result = NodeProperty.parseMatchingExpression("key=value");
        Assert.assertEquals("wrong key", "key", result.getPropertyURI());
        Assert.assertEquals("wrong value", "value", result.getPropertyValue());
    }

    @Test
    public void testMatches()
    {
        NodeProperty test = new NodeProperty("uri", "NodeProperty");

        Assert.assertTrue("should have matched", test.matches("NodeProperty"));
        Assert.assertTrue("should have matched", test.matches("Node*Property"));
        Assert.assertTrue("should have matched", test.matches("*NodeProperty"));
        Assert.assertTrue("should have matched", test.matches("NodeProperty*"));
        Assert.assertTrue("should have matched", test.matches("*NodeProperty*"));
        Assert.assertTrue("should have matched", test.matches("No*P*y"));
        Assert.assertTrue("should have matched", test.matches("*roper*"));
        Assert.assertTrue("should have matched", test.matches("N**Property"));

        Assert.assertTrue("should have matched", test.matches("N.deProperty"));
        Assert.assertTrue("should have matched", test.matches(".odeProperty"));
        Assert.assertTrue("should have matched", test.matches("NodePropert."));
        Assert.assertTrue("should have matched", test.matches("N.de......ty"));

        Assert.assertTrue("should have matched", test.matches("N.*Property"));
        Assert.assertTrue("should have matched", test.matches(".ode*"));

        Assert.assertFalse("should not have matched", test.matches("NodeProperty2"));
        Assert.assertFalse("should not have matched", test.matches("Noe*Property"));
        Assert.assertFalse("should not have matched", test.matches("Property*"));
        Assert.assertFalse("should not have matched", test.matches("Node"));
        Assert.assertFalse("should not have matched", test.matches("*Node"));
        Assert.assertFalse("should not have matched", test.matches("Node* Property"));
    }

}