package servidor;

import java.awt.FontFormatException;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import utils.Seguridad;

public class Protocolo
{

    public Protocolo()
    {
    }

    private static void printError(Exception e)
    {
        System.out.println(e.getMessage());
        e.printStackTrace();
    }

    private static String read(BufferedReader reader)
        throws IOException
    {
        String linea = reader.readLine();
        System.out.println((new StringBuilder("<<PATN: ")).append(linea).toString());
        return linea;
    }

    private static void write(PrintWriter writer, String msg)
    {
        writer.println(msg);
        System.out.println((new StringBuilder(">>SERV: ")).append(msg).toString());
    }

    public static void atenderCliente(Socket s)
    {
        PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
        BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String linea = read(reader);
        if(!linea.equals("INFORMAR"))
        {
            write(writer, "Error en el formato. Cerrando conexion");
            throw new FontFormatException(linea);
        }
        write(writer, "EMPEZAR");
        linea = read(reader);
        if(!linea.contains(":") || !linea.split(":")[0].equals("ALGORITMOS"))
        {
            write(writer, "Error en el formato. Cerrando conexion");
            throw new FontFormatException(linea);
        }
        String algoritmos[] = linea.split(":");
        if(!algoritmos[1].equals("RSA"))
        {
            write(writer, (new StringBuilder("ERROR:Algoritmo no soportado o no reconocido: ")).append(algoritmos[1]).append(". Cerrando conexion").toString());
            throw new NoSuchAlgorithmException();
        }
        if(!algoritmos[2].equals("HMACMD5") && !algoritmos[2].equals("HMACSHA1") && !algoritmos[2].equals("HMACSHA256"))
        {
            write(writer, (new StringBuilder("Algoritmo no soportado o no reconocido: ")).append(algoritmos[2]).append(". Cerrando conexion").toString());
            throw new NoSuchAlgorithmException();
        }
        write(writer, "RTA:OK");
        linea = read(reader);
        num1 = linea.split(":")[0];
        if(!linea.split(":")[1].equals("CERTPA"))
        {
            write(writer, (new StringBuilder("Error en el formato. Cerrando conexion:")).append(linea).toString());
            throw new FontFormatException("CERTPA");
        }
        byte certificadoServidorBytes[] = new byte[520];
        s.getInputStream().read(certificadoServidorBytes);
        try
        {
            CertificateFactory creador = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
            X509Certificate certificadoPuntoAtencion = (X509Certificate)creador.generateCertificate(in);
            write(writer, "RTA:OK");
        }
        catch(Exception e)
        {
            write(writer, "RTA:ERROR");
            write(writer, e.getMessage());
            throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
        }
        num2 = (new StringBuilder()).append(Math.random()).toString();
        write(writer, (new StringBuilder(String.valueOf(num2))).append(":").append("CERTSRV").toString());
        KeyPair keyPair = Seguridad.generateRSAKeyPair();
        try
        {
            X509Certificate certSer = Seguridad.generateV3Certificate(keyPair);
            s.getOutputStream().write(certSer.getEncoded());
            s.getOutputStream().flush();
        }
        catch(Exception exception) { }
        linea = read(reader);
        if(!linea.split(":")[1].equals("OK"))
            write(writer, (new StringBuilder("Error confirmando recepcion de numero cifrado. Cerrando conexion:")).append(linea).toString());
        write(writer, num1);
        linea = read(reader);
        if(!linea.split(":")[1].equals("OK"))
            write(writer, (new StringBuilder("Error confirmando recepcion de numero cifrado. Cerrando conexion:")).append(linea).toString());
        linea = read(reader);
        if(linea.equals(num2))
        {
            write(writer, "RTA:OK");
        } else
        {
            write(writer, "RTA:ERROR");
            write(writer, "El numero no corresponde con el enviado, cerrando conexi\363n");
            throw new FontFormatException(linea);
        }
        linea = read(reader);
        linea = read(reader);
        String ordenes = linea;
        linea = read(reader);
        String ordenes2 = linea;
        if(ordenes.equals(ordenes2))
        {
            write(writer, "RTA:OK");
            write(writer, "Termino requerimientos del cliente en perfectas condiciones.");
        } else
        {
            write(writer, "RTA:ERROR");
            write(writer, "El resumen digital no correspone a las ordenes enviadas, el archivo se encuentra corrupto");
        }
        break MISSING_BLOCK_LABEL_787;
        NullPointerException e;
        e;
        printError(e);
        try
        {
            s.close();
        }
        catch(Exception exception2) { }
        break MISSING_BLOCK_LABEL_796;
        e;
        printError(e);
        try
        {
            s.close();
        }
        catch(Exception exception3) { }
        break MISSING_BLOCK_LABEL_796;
        e;
        printError(e);
        try
        {
            s.close();
        }
        catch(Exception exception4) { }
        break MISSING_BLOCK_LABEL_796;
        e;
        printError(e);
        try
        {
            s.close();
        }
        catch(Exception exception5) { }
        break MISSING_BLOCK_LABEL_796;
        e;
        printError(e);
        try
        {
            s.close();
        }
        catch(Exception exception6) { }
        break MISSING_BLOCK_LABEL_796;
        e;
        e.printStackTrace();
        try
        {
            s.close();
        }
        catch(Exception exception7) { }
        break MISSING_BLOCK_LABEL_796;
        Exception exception1;
        exception1;
        try
        {
            s.close();
        }
        catch(Exception exception8) { }
        throw exception1;
        try
        {
            s.close();
        }
        catch(Exception exception9) { }
    }

    public static final boolean SHOW_ERROR = true;
    public static final boolean SHOW_S_TRACE = true;
    public static final boolean SHOW_IN = true;
    public static final boolean SHOW_OUT = true;
    public static final String EMPEZAR = "EMPEZAR";
    public static final String OK = "OK";
    public static final String ALGORITMOS = "ALGORITMOS";
    public static final String RSA = "RSA";
    public static final String HMACMD5 = "HMACMD5";
    public static final String HMACSHA1 = "HMACSHA1";
    public static final String HMACSHA256 = "HMACSHA256";
    public static final String CERTSRV = "CERTSRV";
    public static final String CERTPA = "CERTPA";
    public static final String SEPARADOR = ":";
    public static final String INFORMAR = "INFORMAR";
    public static final String INIT = "INIT";
    public static final String RTA = "RTA";
    public static final String INFO = "INFO";
    public static final String ERROR = "ERROR";
    public static final String ERROR_FORMATO = "Error en el formato. Cerrando conexion";
    public static final String ERROR_CONFIRMACION = "Error confirmando recepcion de numero cifrado. Cerrando conexion";
    public static String num1;
    public static String num2;
}
Privacy Policy