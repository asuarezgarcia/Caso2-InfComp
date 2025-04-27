package Caso2.Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Caso2.Servidor.Algoritmos;


public class ThreadCliente extends Thread {
    
    // Atributos
    private Socket socket = null; // Socket del cliente
    private PublicKey llavePublica = null; // Guarda llave pública del servidor 
    private IvParameterSpec iv = null ;
    private byte[] llaveSimetrica = null;
    private SecretKey K_AB1 = null;
    private byte[] K_AB2 = null;
    private String ipCliente = null;
    private int idCli = 0; // Contador para los hilos

    // Constructor
    public ThreadCliente(Socket socket, String ipCliente, int idCli) {
        this.socket = socket; // Inicializar el socket del cliente
        this.ipCliente = ipCliente; // Inicializar la IP del cliente
        this.idCli = idCli; // Inicializar el id del cliente
    }

    // run
    public void run() {
        System.out.println("Cliente conectado: " + socket.getInetAddress()); // Imprimir IP del cliente conectado
        
        try {
            // se conectan los flujos para leer y escribir
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);

            //0b leer llave publica del servidor en el archivo 
            try {
                llavePublica = Algoritmos.leerLlavePublica("llavePublica.key");
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace(); 
                throw new RuntimeException("Error al leer la llave pública del servidor", e);
            } 

            // Paso 1: enviar "HELLO"
            escritor.println("HELLO"); // Enviar mensaje de saludo al servidor

            //Paso 2a: Genero el reto numero aleatorio y lo mando 
            SecureRandom random = new SecureRandom();
            int reto = random.nextInt(10000); // Número aleatorio entre 0 y 9999  
            String retoString = String.valueOf(reto); // Convertir reto a string
            escritor.println(retoString); // Enviar el reto al servidor 

            //Paso 5a: Decifrar respuesta con la llave publica del servidor (R) y verificar igualdad al reto, si esta bien mando OK o ERROR 
            String respuesta = lector.readLine(); // Leer respuesta del servidor
            byte [] respBytes = Base64.getDecoder().decode(respuesta); // Pasar respuesta a bytes
            byte [] decifrado = Algoritmos.RSA(llavePublica, respBytes, false); // Decifrar respuesta con llave pública  

            byte[] retoBytes = retoString.getBytes(); // Convertir reto a bytes
            if (Algoritmos.verificar(retoBytes, decifrado)) { // Verificar si el reto coincide
                escritor.println("OK"); // Enviar OK al servidor
                System.out.println("Reto correcto"); // Imprimir reto correcto
            } else {
                escritor.println("ERROR"); // Enviar ERROR al servidor
                System.out.println("Reto incorrecto"); // Imprimir reto incorrecto
                return; // Salir si el reto no coincide
            }

            //Paso 9 y 10: Recibo G,P,G^x mod p, y la firma. Verifico la firma y mando OK o ERROR
            String p = lector.readLine(); // Leer G
            System.out.println("P recibido: " + p); // Imprimir P
            String g = lector.readLine(); // Leer P
            String gxModP = lector.readLine(); // Leer G^x mod p
            String firmaBase64 = lector.readLine(); // Leer firma del servidor

            try{
                //Sacar hash del mensaje usado para firmar
                String mensajeRecibido = p + ';' + g + ';' + gxModP;
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashCalculado = digest.digest(mensajeRecibido.getBytes("UTF-8")); // Calcular hash del mensaje recibido
                
                    //Decifrar firma
                byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64); // Decodificar la firma de Base64
                byte[] hashDescifrado = Algoritmos.RSA(llavePublica, firmaBytes, false); // Descifrar la firma con la llave pública
                    
                    // Verificar la firma y responder
                if (Algoritmos.verificar(hashCalculado, hashDescifrado)) {
                    escritor.println("OK"); // Enviar OK al servidor si la firma es válida
                } else {
                    escritor.println("ERROR"); // Enviar ERROR al servidor si la firma no es válida
                    return; // Salir si la firma no es válida
                }
            } catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }

            //Paso 11a: Calculo (G^x mod p)^y, enviar G^y mod p al servidor
            try { 
                // Crear llaves pública y privada DH
                BigInteger pBig = new BigInteger(p); 
                BigInteger gBig = new BigInteger(g); 
                KeyPair llavesDH = Algoritmos.clienteDiffieHellman1(pBig, gBig); // Generar llaves Diffie-Hellman
                
                    // Enviar G^y mod p al servidor
                Key llavePublicaCliente = llavesDH.getPublic(); // Obtener llave privada del cliente   
                String gyModPBase64 = Base64.getEncoder().encodeToString(llavePublicaCliente.getEncoded());
                escritor.println(gyModPBase64); // Enviar G^y mod P al servidor
                System.out.println("Llave pública enviada al servidor: " + gyModPBase64); // Imprimir llave pública enviada al servidor     

                    // Reconstruir llave pública servidor
                byte[] gxBytes = Base64.getDecoder().decode(gxModP); // Decodificar G^x mod P
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                PublicKey llavePublicaServidor = keyFactory.generatePublic(new X509EncodedKeySpec(gxBytes));
                System.out.println("Llave pública del servidor reconstruida.");

                    // Generar llave privada              
                byte [] llaveSimetrica = Algoritmos.DiffieHellman2(llavesDH.getPrivate(), llavePublicaServidor);
                this.llaveSimetrica = llaveSimetrica; // Guardar llave simétrica en la clase Cliente

                // Generar K_AB1 y K_AB2
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

            // Paso 12b: Crear y enviar IV
            try { 
                byte[] iv = Algoritmos.generarIV();
                this.iv = new IvParameterSpec(iv);
                String ivBase64 = Base64.getEncoder().encodeToString(iv); // Convertir IV a Base64
                escritor.println(ivBase64);
                System.out.println("IV enviado al servidor: " + Base64.getEncoder().encodeToString(iv)); // Imprimir IV enviado al servidor
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Paso 13b: Recibir tabla de servicios cifrada y verficar HMAC
                // Leer tabla de servicios y decifrarla
            String Servicios = lector.readLine(); // Leer tabla de servicios cifrada
            System.out.println("Tabla de servicios recibida: " + Servicios); // Imprimir tabla de servicios recibida
            byte[] serviciosDecifrados = Algoritmos.AES(K_AB1, Servicios, iv, false); // Descifrar id de servicio
            String serviciosString = Base64.getEncoder().encodeToString(serviciosDecifrados); // Convertir a string
            System.out.println("Tabla de servicios decifrada: " + serviciosString); // Imprimir tabla de servicios decifrada

                // Escoger un servicio al azar
            List<String> listaServicios = List.of(serviciosString.split(";")); // Separar los servicios por ";"
            Random random1 = new Random(); // Crear objeto Random para seleccionar un servicio al azar
            int ran = random1.nextInt(listaServicios.size()); // Generar índice aleatorio
            String idServicio = listaServicios.get(ran); // Obtener servicio
            System.out.println("Servicio elegido: " + idServicio); // Imprimir servicio elegido
                
                //Verificar HMAC
            String hmacRecibido = lector.readLine(); // Leer HMAC recibido
            System.out.println("HMAC recibido: " + hmacRecibido); // Imprimir HMAC recibido
            byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido); // Decodificar HMAC recibido
            
                // Calcular HMAC localmente
            try {
                byte[] hmacCalculado = Algoritmos.calculoHMac(K_AB2, serviciosDecifrados); // Calcular HMAC localmente
                
                // Verificar HMAC
                if(Algoritmos.verificar(hmacRecibidoBytes, hmacCalculado)) { // Verificar HMAC
                    System.out.println("HMAC 1 correcto"); // Imprimir HMAC correcto 
                } else {
                    System.out.println("HMAC 1 incorrecto"); // Imprimir HMAC incorrecto 
                    return; // Terminar el hilo si hay error
            }
            } catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }

                

            // Paso 14: Enviar id servicio + ip cliente cifrados
                // Cifrar y enviar id de servicio al servidor + ipCliente
            String mensaje = idServicio + ";" + ipCliente;
            byte[] mensajeCifrado = Algoritmos.AES(K_AB1, mensaje, iv, true); // Cifrar el mensaje 
            escritor.println(Base64.getEncoder().encodeToString(mensajeCifrado));
            System.out.println("idServicio + ipcliente enviados: " + Base64.getEncoder().encodeToString(mensajeCifrado)); // Imprimir mensaje cifrado enviado al servidor

                // Enviar HMAC al servidor
            try{
                byte[] hmac = Algoritmos.calculoHMac(K_AB2, mensajeCifrado); // Calcular HMAC
                escritor.println(Base64.getEncoder().encodeToString(hmac)); // Enviar HMAC al cliente
                System.out.println("HMAC 2 enviado: " + Base64.getEncoder().encodeToString(hmac)); // Imprimir HMAC enviado al servidor
            } catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }

            // Paso 17: Recibir ipServicio y Puerto, y verficar HMAC
                // Leer ipServicio;Puerto cifrados
            String recibido = lector.readLine(); // Leer tabla de servicios cifrada
            byte[] recibDecifrado = Algoritmos.AES(K_AB1, recibido, iv, false); // Descifrar 
            String recibString = new String(recibDecifrado); // Convertir a string

                // Escoger un servicio al azar
            List<String> Info = List.of(recibString.split(";")); // Separar los servicios por ";"

                //Verificar HMAC
            String hmacRecib = lector.readLine(); // Leer HMAC recibido
            byte[] hmacRecibBytes = Base64.getDecoder().decode(hmacRecib); // Decodificar HMAC recibido
            if(Algoritmos.verificar(hmacRecibBytes, K_AB2)) { // Verificar HMAC
                // Paso 18: Respuesta final
                escritor.println("OK"); 
                System.out.println("HMAC 3 correcto"); // Imprimir HMAC correcto 
            } else {
                System.out.println("HMAC 3 incorrecto"); // Imprimir HMAC incorrecto 
                return; // Terminar el hilo si hay error
            }  
            
            // Se cierran flujos y socket
            lector.close();
            escritor.close();
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
