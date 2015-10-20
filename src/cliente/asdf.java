package servidor;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.io.InputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import javax.crypto.spec.SecretKeySpec;
import utils.Transformacion;
import java.security.Key;
import utils.Seguridad;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.NoSuchAlgorithmException;
import java.awt.FontFormatException;
import java.io.Reader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.BufferedReader;

public class Protocolo
{
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
    
    private static void printError(final Exception e) {
        System.out.println(e.getMessage());
        e.printStackTrace();
    }
    
    private static String read(final BufferedReader reader) throws IOException {
        final String linea = reader.readLine();
        System.out.println("<<PATN: " + linea);
        return linea;
    }
    
    private static void write(final PrintWriter writer, final String msg) {
        writer.println(msg);
        System.out.println(">>SERV: " + msg);
    }
    
    public static void atenderCliente(final Socket s) {
        Label_1186: {
            try {
                final PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
                final BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
                String linea = read(reader);
                if (!linea.equals("INFORMAR")) {
                    write(writer, "Error en el formato. Cerrando conexion");
                    throw new FontFormatException(linea);
                }
                write(writer, "EMPEZAR");
                linea = read(reader);
                if (!linea.contains(":") || !linea.split(":")[0].equals("ALGORITMOS")) {
                    write(writer, "Error en el formato. Cerrando conexion");
                    throw new FontFormatException(linea);
                }
                final String[] algoritmos = linea.split(":");
                if (!algoritmos[1].equals("RSA")) {
                    write(writer, "ERROR:Algoritmo no soportado o no reconocido: " + algoritmos[1] + ". Cerrando conexion");
                    throw new NoSuchAlgorithmException();
                }
                if (!algoritmos[2].equals("HMACMD5") && !algoritmos[2].equals("HMACSHA1") && !algoritmos[2].equals("HMACSHA256")) {
                    write(writer, "Algoritmo no soportado o no reconocido: " + algoritmos[2] + ". Cerrando conexion");
                    throw new NoSuchAlgorithmException();
                }
                write(writer, "RTA:OK");
                linea = read(reader);
                Protocolo.num1 = linea.split(":")[0];
                if (!linea.split(":")[1].equals("CERTPA")) {
                    write(writer, "Error en el formato. Cerrando conexion:" + linea);
                    throw new FontFormatException("CERTPA");
                }
                final byte[] certificadoServidorBytes = new byte[520];
                s.getInputStream().read(certificadoServidorBytes);
                X509Certificate certificadoPuntoAtencion;
                try {
                    final CertificateFactory creador = CertificateFactory.getInstance("X.509");
                    final InputStream in = new ByteArrayInputStream(certificadoServidorBytes);
                    certificadoPuntoAtencion = (X509Certificate)creador.generateCertificate(in);
                    write(writer, "RTA:OK");
                }
                catch (Exception e) {
                    write(writer, "RTA:ERROR");
                    write(writer, e.getMessage());
                    throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
                }
                Protocolo.num2 = new StringBuilder().append(Math.random()).toString();
                write(writer, String.valueOf(Protocolo.num2) + ":" + "CERTSRV");
                final KeyPair keyPair = Seguridad.generateRSAKeyPair();
                try {
                    final X509Certificate certSer = Seguridad.generateV3Certificate(keyPair);
                    s.getOutputStream().write(certSer.getEncoded());
                    s.getOutputStream().flush();
                }
                catch (Exception ex) {}
                linea = read(reader);
                if (!linea.split(":")[1].equals("OK")) {
                    write(writer, "Error confirmando recepcion de numero cifrado. Cerrando conexion:" + linea);
                }
                final byte[] cyphNum = Seguridad.asymmetricEncryption(Protocolo.num1.getBytes(), keyPair.getPrivate(), algoritmos[1]);
                write(writer, Transformacion.codificar(cyphNum));
                linea = read(reader);
                if (!linea.split(":")[1].equals("OK")) {
                    write(writer, "Error confirmando recepcion de numero cifrado. Cerrando conexion:" + linea);
                }
                linea = read(reader);
                final byte[] num2Ciph = Transformacion.decodificar(linea);
                final byte[] num2UnCiph = Seguridad.asymmetricDecryption(num2Ciph, certificadoPuntoAtencion.getPublicKey(), algoritmos[1]);
                if (!new String(num2UnCiph).equals(Protocolo.num2)) {
                    write(writer, "RTA:ERROR");
                    write(writer, "El numero no corresponde con el enviado, cerrando conexi\u00f3n");
                    throw new FontFormatException(linea);
                }
                write(writer, "RTA:OK");
                linea = read(reader);
                final byte[] simCiph = Transformacion.decodificar(linea.split(":")[1]);
                final byte[] sim1ciph = new byte[128];
                final byte[] sim2ciph = new byte[128];
                for (int i = 0; i < 128; ++i) {
                    sim1ciph[i] = simCiph[i];
                }
                for (int i = 128; i < 256; ++i) {
                    sim2ciph[i - 128] = simCiph[i];
                }
                byte[] sim1a = new byte[117];
                byte[] sim2a = new byte[11];
                sim2a = Seguridad.asymmetricDecryption(sim2ciph, certificadoPuntoAtencion.getPublicKey(), algoritmos[1]);
                sim1a = Seguridad.asymmetricDecryption(sim1ciph, certificadoPuntoAtencion.getPublicKey(), algoritmos[1]);
                final byte[] simciphc = new byte[128];
                for (int j = 0; j < 117; ++j) {
                    simciphc[j] = sim1a[j];
                }
                for (int j = 117; j < 128; ++j) {
                    simciphc[j] = sim2a[j - 117];
                }
                final byte[] llavesimetricadesifrada = Seguridad.asymmetricDecryption(simciphc, keyPair.getPrivate(), algoritmos[1]);
                final SecretKey sime = new SecretKeySpec(llavesimetricadesifrada, algoritmos[2]);
                linea = read(reader);
                final String ordenes = new String(Seguridad.asymmetricDecryption(Transformacion.decodificar(linea), keyPair.getPrivate(), algoritmos[1]));
                linea = read(reader);
                final byte[] hmac = Seguridad.asymmetricDecryption(Transformacion.decodificar(linea), keyPair.getPrivate(), algoritmos[1]);
                final boolean verificacion = Seguridad.verificarIntegridad(ordenes.getBytes(), sime, algoritmos[2], hmac);
                if (verificacion) {
                    write(writer, "RTA:OK");
                    write(writer, "Termino requerimientos del cliente en perfectas condiciones.");
                    break Label_1186;
                }
                write(writer, "RTA:ERROR");
                write(writer, "El resumen digital no correspone a las ordenes enviadas, el archivo se encuentra corrupto");
            }
            catch (NullPointerException e2) {
                printError(e2);
            }
            catch (IOException e3) {
                printError(e3);
            }
            catch (FontFormatException e4) {
                printError(e4);
            }
            catch (NoSuchAlgorithmException e5) {
                printError(e5);
            }
            catch (InvalidKeyException e6) {
                printError(e6);
            }
            catch (IllegalStateException e7) {
                printError(e7);
            }
            catch (NoSuchPaddingException e8) {
                printError(e8);
            }
            catch (IllegalBlockSizeException e9) {
                printError(e9);
            }
            catch (BadPaddingException e10) {
                printError(e10);
            }
            catch (Exception e11) {
                e11.printStackTrace();
            }
            finally {
                try {
                    s.close();
                }
                catch (Exception ex2) {}
            }
            try {
                s.close();
            }
            catch (Exception ex3) {}
        }
    }
}