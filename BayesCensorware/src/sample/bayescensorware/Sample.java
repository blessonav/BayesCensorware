package sample.bayescensorware;

/*import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public class Sample {

	public static void main(String[] args) throws IOException {
		URL url = new URL("http://cbsenet.nic.in/");
		URLConnection con = url.openConnection();
		InputStream in = con.getInputStream();
		String encoding = con.getContentEncoding();  // ** WRONG: should use "con.getContentType()" instead but it returns something like "text/html; charset=UTF-8" so this value must be parsed to extract the actual encoding
		encoding = encoding == null ? "UTF-8" : encoding;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[8192];
		int len = 0;
		while ((len = in.read(buf)) != -1) {
		    baos.write(buf, 0, len);
		}
		String body = new String(baos.toByteArray(), encoding);
		System.out.println(body);
	}

}
*/



import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
 
public class Sample {
	public static void main(String[] args) {
        try {
            URL google = new URL("http://zetcode.com/articles/javareadwebpage/");
            BufferedReader in = new BufferedReader(new InputStreamReader(google.openStream()));
            String inputLine; 
 
            while ((inputLine = in.readLine()) != null) {
                // Process each line.
                System.out.println(inputLine);
            }
            in.close(); 
 
        } catch (MalformedURLException me) {
            System.out.println(me); 
 
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }//end main
}