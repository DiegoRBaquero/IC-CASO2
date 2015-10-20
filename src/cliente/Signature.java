
package cliente;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signature {
	
    public  static  byte[] HMAC_MD5_encode(String key, String message) throws Exception 
    {

        SecretKeySpec keySpec = new SecretKeySpec(
                key.getBytes(),
                "HmacMD5");

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(keySpec);
        byte[] rawHmac = mac.doFinal(message.getBytes());
          return rawHmac;
    }
}