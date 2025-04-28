package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Aquí se maneja cada conexión de cliente en un hilo separado.
// Se manejan los enviós y recepciones del orden de diferentes mensajes
// y se llaman a las diferentes clases que encriptan
public class ThreadServPrincipal extends Thread {
    
    // Atributos
    private Socket sktCli = null;
    private int id; // Atributo para identificar el thread
    private PublicKey llavePublica = null; // Guarda llave pública RSA
    private PrivateKey llavePrivada = null; // Guarda llave privada RSA
    private KeyPair parLlavesDH = null; // Guarda llaves DH
    private byte[] llaveSimetrica = null; // Guarda llave simétrica AES
    private SecretKey K_AB1 = null; // Guarda K_AB1
    private byte[] K_AB2 = null; // Guarda K_AB2
    private IvParameterSpec iv = null; // Guarda IV para AES

    // Constructor
    public ThreadServPrincipal(Socket socket, int id) {
        this.sktCli = socket;
        this.id = id;
    }

    // run
    public void run() {
        System.out.println("Inicio de un nuevo thread: " + id);

        try {
            // se conectan los flujos para leer y escribir
            BufferedReader lector = new BufferedReader(new InputStreamReader(sktCli.getInputStream()));
            PrintWriter escritor = new PrintWriter(sktCli.getOutputStream(), true);

            // Paso 0a: Leer llaves pública y privada
            try {
                this.llavePublica = Algoritmos.leerLlavePublica("llavePublica.key"); // Leer llave pública
                this.llavePrivada = Algoritmos.leerLlavePrivada("llavePrivada.key"); // Leer llave privada
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                throw new RuntimeException("Error al leer la llaves pública y privada", e);
            }

            // Paso 1: Leer "HELLO" del cliente
            String saludo = lector.readLine(); // Leer saludo del cliente
            if (saludo.equals("HELLO")) { // Saludo correcto
                System.out.println("Saludo correcto del cliente: " + saludo); // Imprimir saludo correcto
            } else {
                System.out.println("Error en el saludo del cliente: " + saludo); // Imprimir error en el saludo
                return; // Terminar el hilo si hay error
            }
            
            // Paso 2b, 3 y 4: Recibir reto (número aleatorio), calcular ruta con Rta con RSA y enviarlo
            String reto = lector.readLine(); // Leer reto
            byte[] Rta = Algoritmos.RSA(llavePrivada, reto.getBytes(), true); // Cifrar el reto con la llave privada
            String rptBase64 = Base64.getEncoder().encodeToString(Rta); // Convertir reto cifrado a Base64
            escritor.println(rptBase64); // Enviar el reto cifrado al cliente

            // Recibir ok o error
            String respuesta1 = lector.readLine(); // Leer respuesta del cliente
            if (respuesta1.equals("ERROR")) { // Si la respuesta es Error
                System.out.println("Error en la conexión, cerrando el hilo."); // Imprimir error
                return; // Terminar el hilo si hay error
            } else if (respuesta1.equals("OK")) { // Si la respuesta es OK
                System.out.println("Respuesta correcta del cliente: " + respuesta1); // Imprimir respuesta correcta
            }

            // Paso 7: Generar G, P, G^x, y F(K_w-, (G, P, G^x)) con DiffieHellman1
            try {
                // Obtener llaves con DH1
                KeyPair parLlaves = Algoritmos.servDiffieHellman1(); // Generar par de llaves
                PublicKey dhPublica = parLlaves.getPublic(); // Obtener llave pública

                // Guardar llaves DH en atributo
                this.parLlavesDH = parLlaves; 

                // Obtener parámetros DH
                DHParameterSpec dhSpec = ((DHPublicKey) dhPublica).getParams(); // Obtener parámetros DH
                BigInteger g = dhSpec.getG(); // Obtener G
                BigInteger p = dhSpec.getP(); // Obtener P
                String Gx = new String(Base64.getEncoder().encode(dhPublica.getEncoded()));
                String enviar = p + ";" + g + ";" + Gx; // Crear string con G, P y G^x

                // Firmar mensaje
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(enviar.getBytes()); // Calcular hash del mensaje

                byte[] firma = Algoritmos.RSA(llavePrivada, hash, true); // Firmar el mensaje con la llave privada
                String firmaBase64 = Base64.getEncoder().encodeToString(firma); // Convertir firma a Base64

                // Enviar P, G y G^x mod P al cliente firmado con llave pública RSA
                escritor.println(p.toString()); // Enviar P
                escritor.println(g.toString()); // Enviar G
                escritor.println(Base64.getEncoder().encodeToString(dhPublica.getEncoded())); // Enviar G^x mod P
                escritor.println(firmaBase64); // Enviar firma
            } catch (Exception e) {
                e.printStackTrace();
            }
            

            // Recibir ok o error
            String respuesta2 = lector.readLine(); // Leer respuesta del cliente
            if (respuesta2.equals("ERROR")) { // Si la respuesta es Error
                System.out.println("Error en la conexión, cerrando el hilo."); // Imprimir error
                return; // Terminar el hilo si hay error
            } else {
                System.out.println("Respuesta del cliente: " + respuesta2); // Imprimir respuesta correcta
            }

            // Paso 11b: Recibe G^y, luego calcula (G^y)^x con DiffieHellman2
            String gY = lector.readLine(); // Leer G^y del cliente
            byte[] gYBytes = Base64.getDecoder().decode(gY); // Decodificar G^y de Base64

            String IV = lector.readLine(); // Leer IV del cliente
            byte[] ivBytes = Base64.getDecoder().decode(IV); // Decodificar IV de Base64
            this.iv = new IvParameterSpec(ivBytes);


            try{
                // Reconstruir llave pública recibida
                KeyFactory keyFactory = KeyFactory.getInstance("DH"); // Crear generador de llaves DH
                PublicKey llPublicaRecibida = keyFactory.generatePublic(new X509EncodedKeySpec(gYBytes)); // Generar llave pública DH

                // Calcular llave simétrica
                byte[] llaveSimetrica = Algoritmos.DiffieHellman2( parLlavesDH.getPrivate(), llPublicaRecibida); // Calcular llave simétrica 
                
                this.llaveSimetrica = llaveSimetrica; // Guardar llave simétrica en atributo

            } catch (Exception e) {
                e.printStackTrace();
            }
            
            // Paso 11b.2: calcula  K_AB1 y MAC K_AB2 
            try {
                byte[] resultDigest = Algoritmos.Digest(llaveSimetrica); // Calcular K_AB1 con digest
                
                // Dividir el digest en dos partes
                int mitad = resultDigest.length / 2;
                byte[] KAB1 = new byte[mitad];
                byte[] KAB2 = new byte[mitad];
                System.arraycopy(resultDigest, 0, KAB1, 0, mitad); // 1era mitad K_AB1
                System.arraycopy(resultDigest, mitad, KAB2, 0, mitad); // 2nda mitad K_AB2

                // Crear llaves
                this.K_AB1 = new SecretKeySpec(KAB1, "AES");
                this.K_AB2 = KAB2;

            } catch (Exception e) {
                e.printStackTrace();
            }
            
            // Paso 13: Cifrar y enviar C(K_AB1, tabla_ids_servicios) y HMAC(MAC K_AB2, tabla_ids_servicios)
                // Enviar tabla
            ArrayList<ArrayList<String>> servidores = ServPrincipal.getTablaServidores(); // Obtener tabla de servidores
            String envioTabla = "";
            for (int i = 0; i < servidores.size(); i++) {
                String serv = servidores.get(i).get(0); // Agregar id de servicio a la tabla
                envioTabla += serv + ";"; // Agregar id al envio de la tabla
            }

            try {
                String cifrado = Algoritmos.AES_Cifrado(envioTabla, K_AB1, iv); // Cifrar id de servicio con AES
                escritor.println(cifrado); // Enviar id de servicio cifrado al cliente
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Error al cifrar la tabla de servicios", e);
            }

                // Enviar HMAC
            byte[] TablaBytes = envioTabla.getBytes(); // Pasar bytes de la tabla
            try {
                byte[] hmac = Algoritmos.calculoHMac(K_AB2, TablaBytes); // Calcular HMAC 
                String hmacBase64 = Base64.getEncoder().encodeToString(hmac); // Convertir HMAC a Base64
                escritor.println(hmacBase64); // Enviar HMAC al cliente
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Error al calcular HMAC del id de servicio", e);
            }
        
            
            // Paso 15: Verifica HMAC; recibe C(K_AB1, id_servicio + ip_cliente) y HMAC(K_AB2, id_servicio + ip_cliente)
            String idServicioCifrado = lector.readLine(); // Leer id de servicio 

            String serv = ""; // Para guardar el id de servicio buscado
            try{
                // Descifrar id de servicio
                String servIp = Algoritmos.AES_Decifrado(idServicioCifrado, K_AB1, iv); // Descifrar id de servicio
                
                // Separar id de servicio y ip_cliente
                String[] partes = servIp.split(";"); 
                String idServ = partes[0]; // Obtener id de servicio
                serv = idServ; // Guardar id

                // Calcular HMAC localmente
                String hmacRecibido = lector.readLine(); // Leer HMAC recibido

                byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido); // Decodificar HMAC recibido
                byte[] servIpDecifradosBytes = servIp.getBytes(); // Convertir datos descifrados a bytes     
                byte[] hmacCalculado = Algoritmos.calculoHMac(K_AB2, servIpDecifradosBytes); // Calcular HMAC localmente
                
                //Verificar HMAC
                if(!Algoritmos.verificar(hmacRecibidoBytes, hmacCalculado)) { // Verificar HMAC
                    return; // Terminar el hilo si hay error
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Error al descifrar el id de servicio", e);
            }

            
            // Paso 16: Envía C(K_AB1, ip_servidor + puerto_servidor) y HMAC(K_AB2, ip_servidor + puerto_servidor)
                // Enviar ip y puerto
            for (int j = 0; j < servidores.size(); j++) { // Buscamos en la tabla de servicios completa
                if (servidores.get(j).get(0).equals(serv)) { // Hallar servicio buscado

                    // Obtener ip y puerto del servidor, y juntarlos
                    String ipServidor = servidores.get(j).get(2); // Obtener ip del servidor
                    String puertoServidor = servidores.get(j).get(3); // Obtener puerto del servidor
                    String envioIPPuerto = ipServidor + ";" + puertoServidor; // Crear string con ip y puerto

                    try {
                        // Cifrar AES
                        String Cifrado = Algoritmos.AES_Cifrado(envioIPPuerto, K_AB1 , iv); // Cifrar ip

                        escritor.println(Cifrado); // Enviar ip cifrada al cliente

                        // Enviar HMAC
                            byte[] envioIPPuertoBytes = envioIPPuerto.getBytes(); // Pasar envioi a bytes
                            byte[] hmac = Algoritmos.calculoHMac(K_AB2, envioIPPuertoBytes); // Calcular HMAC 
                            String hmacBase64 = Base64.getEncoder().encodeToString(hmac); // Convertir HMAC a Base64
                            escritor.println(hmacBase64); // Enviar HMAC al cliente
                            System.out.println("HMAC 3 enviado: " + hmacBase64); // Imprimir HMAC enviado
                    } catch (Exception e) {
                        e.printStackTrace();
                        throw new RuntimeException("Error al calcular HMAC de la ip y puerto", e);
                    }
                }    
                break;
            }


            // Final: recibe "Ok" o "Error" y termina el hilo
            String respuesta3 = lector.readLine(); // Leer respuesta del cliente
            if (respuesta3.equals("Ok")) { // Si la respuesta es Ok
                System.out.println("Respuesta correcta del cliente: " + respuesta3); // Imprimir respuesta correcta
            } else {
                System.out.println("Error en la respuesta del cliente: " + respuesta3); // Imprimir error en la respuesta
            }


            // Se cierran flujos y socket
            lector.close();
            escritor.close();
            sktCli.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
