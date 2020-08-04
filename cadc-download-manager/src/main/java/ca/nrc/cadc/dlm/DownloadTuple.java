package ca.nrc.cadc.dlm;import ca.nrc.cadc.util.StringUtil;import java.security.InvalidParameterException;import javax.swing.plaf.synth.Region;import org.apache.log4j.Logger;public class DownloadTuple {    private static Logger log = Logger.getLogger(DownloadTuple.class);    //    tupleID (URI) will be translated into URI when needed    //    this format required for use in DownloadIterators    public final String tupleID;    public final String shapeDescriptor;    public final String label;    // unsure we need Region or not - only interesting    // in cadc-download-manager when DataLinkClient is putting    // together cutouts    private Region shape;    /**     * ctor will parse DownloadTuple from input string. Allowed formats for tupleStr:     * - ID - a URI string     * - ID{shape}     * - ID{shape}{label}     * where:     * - ID = URI identifying what to download     * - shape = string descriptor (circle, polygon, etc.) and coordinates for cutout     * - label = used to generate filenames     *     * @param tupleStr     */    public DownloadTuple(String tupleStr) {        log.info("tuple string input: " + tupleStr);        String [] tupleParts = tupleStr.split("\\{");        if (tupleParts.length > 3) {            throw new InvalidParameterException("tuple has too many '{': " + tupleStr);        }        if (tupleParts.length == 3) {            // grab optional third [2] parameter as label            String l = tupleParts[2];            if (l.length() > 1) {                // trim off trailing "}"                this.label = l.substring(0, l.length() - 1);            } else {                // invalid format                throw new InvalidParameterException("Invalid label format: " + tupleStr);            }        } else {            this.label = null;        }        if (tupleParts.length > 1) {            String sd = tupleParts[1];            if (sd.length() > 1) {                // trim off trailing "}"                this.shapeDescriptor = sd.substring(0, sd.length() - 1);            } else {                // invalid format                throw new InvalidParameterException("Invalid shape descriptor: " + tupleStr);            }        } else {            this.shapeDescriptor = null;        }        String uriStr = tupleParts[0];        if (StringUtil.hasLength(uriStr)) {            this.tupleID = uriStr;        } else {            // invalid format - has to at least be a single URI passed in            throw new InvalidParameterException("missing tupleID: " + tupleStr);        }    }    public String toOutputFormat() {        String tupleStr = tupleID;        // This function might be able to provide different formats        // within the shapeDescriptor to substitute whitespace for a different character        if (StringUtil.hasLength(shapeDescriptor)) {            tupleStr += "{" + shapeDescriptor + "}";        }        if (StringUtil.hasLength(label)) {            tupleStr += "{" + label + "}";        }        return tupleStr;    }}