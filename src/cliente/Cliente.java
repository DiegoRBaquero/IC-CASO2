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
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Cliente {
	
	PublicKey key;
	PrivateKey privateKey;
	KeyPair theKey;

	public Cliente() {
		
		
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
			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			KeyPair pair = generator.generateKeyPair();
			 privateKey = pair.getPrivate();
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
			String num=line.split(":")[0];
			byte[] receivedBytes = new byte[520];
			socket.getInputStream().read(receivedBytes);
			System.out.println(receivedBytes[519]);
			try
	        {
	            CertificateFactory creador = CertificateFactory.getInstance("X.509");
	            InputStream in = new ByteArrayInputStream(receivedBytes);
	            X509Certificate certificadoPuntoAtencion = (X509Certificate)creador.generateCertificate(in);
	             key= certificadoPuntoAtencion.getPublicKey();
	             
	            pw.println("RTA:OK");
	            System.out.println(">> RTA:OK");
	        }
	        catch(Exception e)
	        {
	        	pw.write("RTA:ERROR");
	            e.printStackTrace();
	            throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
	        }
			line = br.readLine();
			System.out.println(line);
			
			double receivedNumber2 = Double.parseDouble(descifrar(destransformar(line), key));
			
			if (receivedNumber2!=randomNumber) 
			{
				System.out.println("ERROR");
				 pw.println("RTA:ERROR");
			} else {
				
				System.out.println(line);
				 pw.println("RTA:OK");
				
				 
				 pw.println(transformar(cifrar(num, privateKey)));
			}
			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK")) 
			{
				System.out.println("ERROR");
				
			} 
			else 
			{
				System.out.println(line);
			
			//String s=transformar(cifrarPublica("a",key));
			// cifrar(s,privateKey);
			
				//pw.println("INIT:"+ llave );
				
				//pw.println(transformar(cifrarPublica("ORDENES: 4",key)));
				
				
				//String m="ORDENES :"+ transformar(HMAC_MD5_encode("4444", "4"));
           //pw.println(cifrarPublica(m,key));
			}
				
			
			//line = br.readLine();
			//System.out.println(line);
			
			pw.close();
	     	br.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	public String descifrar(byte[]cipheredText, PublicKey key) {
		
		String codigo= "";
		
		try {
			
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key );
		byte [] clearText = cipher.doFinal(cipheredText);
		String s3 = new String(clearText);
		codigo=s3;
		}
		catch (Exception e) {
		System.out.println("Excepcion: " + e.getMessage());
		}
		return codigo;
		}

	public static byte[] destransformar( String ss)
	{
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	
	public byte[] cifrar(String num, PrivateKey privateKey ) {
		
		
		try {
		KeyPairGenerator generator =
		KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		
		Cipher cipher = Cipher.getInstance("RSA");
		byte [] clearText = num.getBytes();
		String s1 = new String (clearText);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		long startTime = System.nanoTime();
		byte [] cipheredText = cipher.doFinal(clearText);
		long endTime = System.nanoTime();
		System.out.println("clave cifrada: " + cipheredText);
		return cipheredText;
		}
		catch (Exception e) {
		System.out.println("Excepcion: " + e.getMessage());
		return null;
		}
		}


	
public byte[] cifrarPublica(String num, PublicKey privateKey ) {
		
		
		try {
		KeyPairGenerator generator =
		KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		
		Cipher cipher = Cipher.getInstance("RSA");
		byte [] clearText = num.getBytes();
		String s1 = new String (clearText);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		long startTime = System.nanoTime();
		byte [] cipheredText = cipher.doFinal(clearText);
		long endTime = System.nanoTime();
		System.out.println("clave cifrada: " + cipheredText);
		return cipheredText;
		}
		catch (Exception e) {
		System.out.println("Excepcion: " + e.getMessage());
		return null;
		}
		}

	
	public static String transformar( byte[] b )
	{
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
	
	
	
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
