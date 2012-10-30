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

package ca.nrc.cadc.vos.client.ui;


import ca.nrc.cadc.util.Log4jInit;
import ca.nrc.cadc.vos.VOSURI;
import ca.nrc.cadc.vos.client.VOSpaceClient;
import ca.onfire.ak.AbstractApplication;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.Writer;


/**
 * The main class for graphical output display.
 *
 * @author pdowler
 */
public class GraphicUI extends AbstractApplication
        implements ChangeListener, UserInterface
{
    private static final long serialVersionUID = 201210201041L;
    private static Logger LOGGER = Logger.getLogger(GraphicUI.class);

    private JTextArea logTextArea;
    private LogWriter logWriter;
    private JTabbedPane tabPane;
    private JUploadManager uploadManager;

    private final VOSURI targetVOSpaceURI;
    private final VOSpaceClient voSpaceClient;


    public GraphicUI(final Level logLevel, final VOSURI targetVOSpaceURI,
                     final VOSpaceClient voSpaceClient)
    {
        super(new BorderLayout());
        LOGGER.setLevel(logLevel);

        this.targetVOSpaceURI = targetVOSpaceURI;
        this.voSpaceClient = voSpaceClient;
    }


    /**
     * The GUI can be constructed using information from the
     * <code>getApplicationContainer()</code> method, which includes
     * the access to the AppletContext (if in applet mode) and
     * possibly to an ApplicationConfig object.
     */
    @Override
    protected void makeUI()
    {
        tabPane = new JTabbedPane();
        logTextArea = new JTextArea();
        logWriter = new LogWriter(logTextArea);

        Log4jInit.setLevel("ca.nrc.cadc.vospace", LOGGER.getLevel(),
                           getLogWriter());

        addMainPane();
        setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        final JScrollPane sp = createLogScrollPane();
        getTabPane().addTab("Log Messages", sp);

        Util.recursiveSetBackground(this, Color.WHITE);

        try
        {
            final Thread appThread = new Thread()
            {
                /**
                 * If this thread was constructed using a separate
                 * <code>Runnable</code> run object, then that
                 * <code>Runnable</code> object's <code>run</code> method is called;
                 * otherwise, this method does nothing and returns.
                 * <p/>
                 * Subclasses of <code>Thread</code> should override this method.
                 *
                 * @see #start()
                 * @see #stop()
                 */
                @Override
                public void run()
                {
                    try
                    {
                        SwingUtilities.invokeAndWait(new Runnable()
                        {
                            public void run()
                            {
                                selectSourceDirectory(GraphicUI.this,
                                                      new SourceDirectoryChooserCallback()
                                                      {
                                                          @Override
                                                          public void onCallback(final File chosenDirectory)
                                                          {
                                                              setUploadManager(
                                                                      new JUploadManager(chosenDirectory,
                                                                                         getTargetVOSpaceURI(),
                                                                                         getVOSpaceClient()));

                                                              getTabPane().addTab("Upload",
                                                                                  getUploadManager());
                                                              getTabPane().setSelectedIndex(1);

                                                              GraphicUI.this.run();
                                                          }
                                                      });
                            }
                        });
                    }
                    catch (final Exception e)
                    {
                        LOGGER.fatal("Error caught.", e);
                        e.printStackTrace();
                        System.exit(-1);
                    }
                }
            };

            appThread.start();
        }
        catch (Throwable t)
        {
            if (LOGGER.isDebugEnabled())
            {
                LOGGER.error("DelayedInit failed", t);
            }
            else
            {
                LOGGER.error("DelayedInit failed: " + t);
            }
        }
    }

    /**
     * Add the tabbed pane.
     */
    protected void addMainPane()
    {
        add(getTabPane(), BorderLayout.CENTER);
    }

    /**
     * Create an instance of a JScrollPane to contain the log output.
     * @return      The JScrollPane instance.
     */
    protected JScrollPane createLogScrollPane()
    {
        return new JScrollPane(getLogTextArea());
    }

    /**
     * Start the source directory chooser.
     */
    protected void run()
    {
        // Fire off a thread to complete init once the app is displayed on
        // screen.
        new Thread(new DelayedInit()).start();
    }

    /**
     * Invoked when the target of the listener has changed its state.
     *
     * @param e a ChangeEvent object
     */
    @Override
    public void stateChanged(final ChangeEvent e)
    {

    }

    /**
     * The default method always returns true immediately.
     *
     * @return true
     */
    @Override
    public boolean quit()
    {
        final boolean ret = getConfirmation("OK to quit?");

        if (ret && (getUploadManager() != null))
        {
            getUploadManager().stop();
        }

        return ret;
    }

    @Override
    public void start()
    {
        if (getUploadManager() != null)
        {
            getUploadManager().start();
        }
    }

    public JTabbedPane getTabPane()
    {
        return tabPane;
    }

    public LogWriter getLogWriter()
    {
        return logWriter;
    }

    public JTextArea getLogTextArea()
    {
        return logTextArea;
    }

    public JUploadManager getUploadManager()
    {
        return uploadManager;
    }

    public void setUploadManager(final JUploadManager uploadManager)
    {
        this.uploadManager = uploadManager;
    }

    public VOSURI getTargetVOSpaceURI()
    {
        return targetVOSpaceURI;
    }

    public VOSpaceClient getVOSpaceClient()
    {
        return voSpaceClient;
    }

    public void selectSourceDirectory(final Component parent,
                                      final SourceDirectoryChooserCallback callback)
    {
        try
        {
            final SourceDirectoryChooser fileChooser =
                    new SourceDirectoryChooser(null, "sourceFileChooser");
            final int returnVal = fileChooser.showDialog(parent, "Select");

            if (returnVal == JFileChooser.APPROVE_OPTION)
            {
                final File sourceDirectory = fileChooser.getSelectedFile();

                final String estr;
                // in case the user types something in
                if (!sourceDirectory.isDirectory())
                {
                    estr = "'" + sourceDirectory.getAbsolutePath()
                           + "' is not a directory";
                }
                else if (!sourceDirectory.canRead())
                {
                    estr = "'" + sourceDirectory.getAbsolutePath()
                           + "' is not writable";
                }
                else
                {
                    estr = null;
                }

                if (estr != null)
                {
                    JOptionPane.showMessageDialog(parent, estr, "Error",
                                                  JOptionPane.ERROR_MESSAGE);
                    selectSourceDirectory(parent, callback); // recursive
                }
                else
                {
                    LOGGER.info("Source directory: "
                                + sourceDirectory.getAbsolutePath());
                    callback.onCallback(sourceDirectory);
                }
            }
        }
        catch (RuntimeException rex)
        {
            LOGGER.error("Failed to determine Source Directory", rex);
        }
    }


    private class LogWriter extends Writer
    {
        private JTextArea logTextArea;


        LogWriter(final JTextArea textArea)
        {
            super();
            logTextArea = textArea;
        }


        @Override
        public void close() throws IOException
        { }

        @Override
        public void flush() throws IOException
        {

        }

        public JTextArea getLogTextArea()
        {
            return logTextArea;
        }

        @Override
        public void write(final char[] cbuf, final int off, final int len)
                throws IOException
        {
            if (!SwingUtilities.isEventDispatchThread())
            {
                try
                {
                    SwingUtilities.invokeAndWait(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            doWrite(String.copyValueOf(cbuf, off, len));
                        }
                    });
                }
                catch (Throwable t)
                {
                    System.out.println("Error writing to log.");
                    t.printStackTrace();
                }
            }
            else
            {
                doWrite(String.copyValueOf(cbuf, off, len));
            }
        }

        protected void doWrite(final String s)
        {
            if (getLogTextArea() != null)
            {
                getLogTextArea().append(s);
                getLogTextArea().updateUI();
            }
        }
    }

    protected class DelayedInit implements Runnable
    {
        public DelayedInit()
        {

        }

        public void run()
        {
            try
            {
                getUploadManager().start();
            }
            catch (final Throwable t)
            {
                if (LOGGER.isDebugEnabled())
                {
                    LOGGER.error("DelayedInit failed", t);
                }
                else
                {
                    LOGGER.error("DelayedInit failed: " + t);
                }
            }
        }
    }
}