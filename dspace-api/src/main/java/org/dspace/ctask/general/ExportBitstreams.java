/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.ctask.general;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.Writer;
import java.io.OutputStreamWriter;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import org.dspace.content.Bitstream;
import org.dspace.content.BitstreamFormat;
import org.dspace.content.Bundle;
import org.dspace.content.DSpaceObject;
import org.dspace.content.Item;
import org.dspace.core.Context;
import org.dspace.curate.AbstractCurationTask;
import org.dspace.curate.Curator;
import org.dspace.curate.Distributive;
import org.dspace.authorize.AuthorizeException;

/**
 * ExportBitstreams exports all bitstreams found within the specified
 * DSO and saves them to disk with their bitstream name.
 * This version ignores authorizations, so it will export even
 * restricted bitstreams.
 *
 * @author Ivan Masár <helix84@centrum.sk>
 */
@Distributive
public class ExportBitstreams extends AbstractCurationTask
{
    /**
     * Perform the curation task upon passed DSO
     *
     * @param dso the DSpace object
     * @throws IOException
     */
    @Override
    public int perform(DSpaceObject dso) throws IOException
    {
        try {
            // ignore authorization; is there a simpler way?
            Context context = new Context();
            context.turnOffAuthorisationSystem();
            DSpaceObject dso2 = dso.find(context, dso.getType(), dso.getID());
    
            distribute(dso2);
            
            context.restoreAuthSystemState();
        } catch (SQLException e) {
        }
        
        return Curator.CURATE_SUCCESS;
    }
    
    @Override
    protected void performItem(Item item) throws SQLException, IOException
    {
        
        StringBuilder sb = new StringBuilder();
        for (Bundle bundle : item.getBundles())
        {
            for (Bitstream bs : bundle.getBitstreams())	// alternatively, use bundle.getPrimaryBitstreamID()
            {
                String handle = item.getHandle();
                String h = handle.substring(handle.indexOf("/")+1);
                String filename = bs.getName();
                if (filename.indexOf("_dp.") > 0) {
                    try {
                        InputStream file = bs.retrieve();
                        OutputStream out = null;
//                        Writer out = null;
                        
                        // TODO: proper UTF-8 filenames
                        try {
                            String fullpath = "/dspace/exports/exportbitstream/" + filename.substring(0, filename.indexOf(".")) + "_" + h + filename.substring(filename.indexOf("."));
//                            out = new FileOutputStream(fullpath);
                            out = new BufferedOutputStream(new FileOutputStream(fullpath));
//                            out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(fullpath), "UTF-8"));
                            int c;
                            
                            while ((c = file.read()) != -1) {
                                out.write(c);
                            }
                            
                            sb.append(filename + "\n");
// TODO: reporting and status
        report(filename + "\n");
                        } finally {
                            if (out != null) {
                                out.close();
                            }
                        }
                    } catch (AuthorizeException e) {
//                            sb.append("AuthorizeException\n\n");
        report("AuthorizeException\n\n");
                    }
                }
            }           
        }
        
//        report(sb.toString());
        setResult(sb.toString());
    }
}
