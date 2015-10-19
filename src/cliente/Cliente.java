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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Cliente {

	public Cliente() {
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
			//System.out.println(receivedNumber);
			double receivedNumber2 = Double.parseDouble(line);
			if (receivedNumber2!=randomNumber) 
			{
				System.out.println("ERROR");
				 pw.println("RTA:ERROR");
			} else {
				
				System.out.println(line);
				 pw.println("RTA:OK");
				 pw.println(num);
			}
			line = br.readLine();
			if (!line.equalsIgnoreCase("RTA:OK")) 
			{
				System.out.println("ERROR");
				
			} 
			else 
			{
				System.out.println(line);
				pw.println("INIT");
				pw.println("ORDENES : 4");
				pw.println("ORDENES : 4");
			}
			line = br.readLine();
			System.out.println(line);
			pw.close();
	     	br.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
