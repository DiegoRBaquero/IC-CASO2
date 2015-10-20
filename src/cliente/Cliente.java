package cliente;

import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.Key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Cliente {

	PublicKey publicKey;
	PrivateKey privateKey;
	KeyPair theKey;
	PublicKey myPublic;
	static SecretKeySpec other;

	public Cliente() {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator generator1;
		try {
			generator1 = KeyPairGenerator.getInstance("RSA");
			generator1.initialize(1024);
			theKey = generator1.generateKeyPair();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		try {
			Socket socket = new Socket("localhost", 443);
			BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())),
					true);

			System.out.println(">> INFORMAR");
			pw.println("INFORMAR");
			String line = br.readLine();
			if (!line.equalsIgnoreCase("EMPEZAR")) {
				System.out.println("ERROR");
			} else {
				System.out.println(line);
			}

			System.out.println(">> ALGORITMOS:RSA:HMACMD5");
			pw.println("ALGORITMOS:RSA:HMACMD5");
			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK")) {
				System.out.println("ERROR");
			} else {
				System.out.println(line);
			}

			int randomNumber = (int) (Math.random() * 10000);
			System.out.println(">> " + randomNumber + ":CERTPA");
			pw.println(randomNumber + ":CERTPA");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			KeyPair pair = generator.generateKeyPair();
			privateKey = pair.getPrivate();
		    myPublic= pair.getPublic();
			java.security.cert.X509Certificate cert = Certificado.generateV1Certificate(pair);
			byte[] mbyte = cert.getEncoded();
			socket.getOutputStream().write(mbyte);
			socket.getOutputStream().flush();

			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK")) {
				System.out.println("ERROR");
			} else {
				System.out.println(line);
			}
			line = br.readLine();
			if (!line.endsWith("CERTSRV")) {
				System.out.println("ERROR");
			} else {

				System.out.println(line);
			}
			double receivedNumber = Double.parseDouble(line.split(":")[0]);
			String num = line.split(":")[0];
			byte[] receivedBytes = new byte[520];
			socket.getInputStream().read(receivedBytes);
			System.out.println(receivedBytes[519]);
			try {
				CertificateFactory creador = CertificateFactory.getInstance("X.509");
				InputStream in = new ByteArrayInputStream(receivedBytes);
				X509Certificate certificadoPuntoAtencion = (X509Certificate) creador.generateCertificate(in);
				publicKey = certificadoPuntoAtencion.getPublicKey();

				pw.println("RTA:OK");
				System.out.println(">> RTA:OK");
			} catch (Exception e) {
				pw.write("RTA:ERROR");
				e.printStackTrace();
				throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
			}
			line = br.readLine();
			System.out.println(line);

			double receivedNumber2 = Double.parseDouble(descifrar(destransformar(line), publicKey));

			if (receivedNumber2 != randomNumber) {
				System.out.println("ERROR");
				pw.println("RTA:ERROR");
			} else {

				System.out.println(line);
				pw.println("RTA:OK");

				pw.println(transformar(cifrar1(num, privateKey)));
			}
			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK")) {
				System.out.println("ERROR");
			} else {
				System.out.println(line);
			}
			System.out.println("anntes");
			
			SecretKeySpec key = new SecretKeySpec(("1").getBytes("UTF-8"), "HMACMD5");
			System.out.println(key);
			byte[] bytes = cifrar("1", publicKey);
			
			
			byte[] bytes1 = new byte[117];
			byte[] bytes2 = new byte[11];
			
			for (int i = 0; i < 117; ++i) 
			{
                bytes1[i] = bytes[i];
            }
			for (int i = 0; i < 11; ++i) {
                bytes2[i] = bytes[i+117];
            }
			
			
			byte[] bytes1c = cifrar(bytes1, privateKey);
			System.out.println(bytes1c.length);
			byte[] bytes2c = cifrar(bytes2, privateKey);
			System.out.println(bytes2c.length);
			byte[] bytesc = new byte[256];
			for (int i = 0; i < 128; ++i) {
                bytesc[i] = bytes1c[i];
            }
			for (int i = 128; i < 256; ++i) {
                bytesc[i] = bytes2c[i-128];
            }
			
			pw.println("INIT:" + transformar(bytesc));
		      
			
			String ordenes = "ORDENES:o";
			System.out.println(cifrar(ordenes,publicKey));
			pw.println(transformar(cifrar(ordenes, publicKey)));
			    
			
			 
		      
		   // SecretKey sime = new SecretKeySpec(destransformar("1"),"HMACMD5");
			//String hash= transformar(hmacDigest(destransformar("o"),sime, "HMACMD5"));
			
			
			
			byte[] x= hmacDigest(destransformar("o"), key,"HMACMD5");
			String hash2 = "ORDENES:" + transformar(x);
			
			pw.println(transformar(cifrar(hash2, publicKey)));
			
			

			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK"))
			{
				System.out.println("ERROR");
			} else {
				System.out.println(line);
				System.out.println("aqui");
			}

			pw.close();
			br.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String descifrar(byte[] cipheredText, PublicKey key) {

		String codigo = "";

		try {

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			codigo = s3;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return codigo;
	}

	public static byte[] destransformar(String ss) {
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length() / 2];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
		}
		return ret;
	}

	public byte[]cifrar(byte[] msg, PrivateKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		 Cipher decifrador = Cipher.getInstance("RSA");
		    decifrador.init(1, key);
		   
		    return decifrador.doFinal(msg);
	}
	
	public byte[] cifrar1(String num, PrivateKey key) {

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);

			
			Cipher cipher = Cipher.getInstance("RSA");
			byte[] clearText = num.getBytes();
			String s1 = new String(clearText);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			long startTime = System.nanoTime();
			byte[] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("clave cifrada: " + cipheredText);
			return cipheredText;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public byte[] cifrar(String num, PublicKey key) {

		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);

			Cipher cipher = Cipher.getInstance("RSA");
			byte[] clearText = num.getBytes();
			System.out.println(clearText.length);
			String s1 = new String(clearText);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			long startTime = System.nanoTime();
			byte[] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("clave cifrada: " + cipheredText);
			return cipheredText;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String transformar(byte[] b) {
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0; i < b.length; i++) {
			String g = Integer.toHexString(((char) b[i]) & 0x00ff);
			ret += (g.length() == 1 ? "0" : "") + g;
		}
		return ret;
	}

	public static byte[] HMAC_MD5_encode(String key, String message) throws Exception {

		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");

		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(keySpec);
		byte[] rawHmac = mac.doFinal(message.getBytes());
		return rawHmac;
	}
	
	
	
	

	  public static byte[] hmacDigest(byte[] msg, Key key, String algo)
			    throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException
			  {
			    Mac mac = Mac.getInstance(algo);
			    mac.init(key);
			    
			    byte[] bytes = mac.doFinal(msg);
			    return bytes;
			  }
	  
	
	  
	
			  
	  
	
}

