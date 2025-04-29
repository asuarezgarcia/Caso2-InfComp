package Caso2.Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
    private int idCli = 1; // Contador para los hilos 

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
            } else {
                escritor.println("ERROR"); // Enviar ERROR al servidor
                return; // Salir si el reto no coincide
            }

            //Paso 9 y 10: Recibo G,P,G^x mod p, y la firma. Verifico la firma y mando OK o ERROR
            String p = lector.readLine(); // Leer G
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

                    // Reconstruir llave pública servidor
                byte[] gxBytes = Base64.getDecoder().decode(gxModP); // Decodificar G^x mod P
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                PublicKey llavePublicaServidor = keyFactory.generatePublic(new X509EncodedKeySpec(gxBytes));

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
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Paso 13b: Recibir tabla de servicios cifrada y verficar HMAC
                // Leer tabla de servicios y decifrarla
            String Servicios = lector.readLine(); // Leer tabla de servicios cifrada

            try{
                String serviciosDecifrados = Algoritmos.AES_Decifrado(Servicios, K_AB1, iv); // Decifrar tabla de servicios
             
                //Verificar HMAC
                String hmacRecibido = lector.readLine(); // Leer HMAC recibido
            
                // Calcular HMAC localmente
                byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido); // Decodificar HMAC recibido
                byte[] serviciosDecifradosBytes = serviciosDecifrados.getBytes(StandardCharsets.UTF_8); // Convertir datos descifrados a bytes
                long tiempoInicioV = System.nanoTime(); // Iniciar temporizador
                byte[] hmacCalculado = Algoritmos.calculoHMac(K_AB2, serviciosDecifradosBytes); // Calcular HMAC localmente
                
                // Verificar HMAC
                if(!Algoritmos.verificar(hmacRecibidoBytes, hmacCalculado)) { // Verificar HMAC
                    return; // Terminar el hilo si hay error
                } 
                long tiempoFinV = System.nanoTime(); // Detener temporizador
            } catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }
                
            
            // Paso 14: Enviar id servicio + ip cliente cifrados
                
                // Generar id de servicio aleatorio
            Random randomId = new Random(); // Generar id de servicio aleatorio
            int idServicio = randomId.nextInt(2)+1; // Número aleatorio entre 1 y 3
            String idServicioStr = "S" + String.valueOf(idServicio); // Convertir id de servicio a string

            try{
                // Cifrar y enviar id de servicio al servidor + ipCliente
                String mensaje = idServicioStr + ";" + ipCliente;
                String mensajeCifrado = Algoritmos.AES_Cifrado(mensaje, K_AB1, iv); // Cifrar el mensaje 
                escritor.println(mensajeCifrado);

                // Enviar HMAC al servidor
                byte[] mensajeCifradoBytes = mensaje.getBytes(); // Pasar bytes de la tabla
                byte[] hmac = Algoritmos.calculoHMac(K_AB2, mensajeCifradoBytes); // Calcular HMAC
                String hmacBase64 = Base64.getEncoder().encodeToString(hmac); // Convertir HMAC a Base64
                escritor.println(hmacBase64); // Enviar HMAC al cliente
            } catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }            

            // Paso 17: Recibir ipServicio y Puerto, y verficar HMAC
                // Leer ipServicio;Puerto cifrados
            String recibido = lector.readLine(); // Leer tabla de servicios cifrada 

            try{
                // Leer ipServicio;Puerto cifrados y decifrarlo
                String recibDecifrado = Algoritmos.AES_Decifrado(recibido, K_AB1, iv); // Descifrar 

                // Leer HMAC
                String hmacRecibido = lector.readLine(); // Leer HMAC recibido

                // Calular HMAC localmente
                byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido); // Decodificar HMAC recibido
                byte[] recibDecifradoBytes = recibDecifrado.getBytes(StandardCharsets.UTF_8); // Convertir datos descifrados a bytes 
                long tiempoInicioV = System.nanoTime(); // Iniciar temporizador
                byte[] hmacCalculado = Algoritmos.calculoHMac(K_AB2, recibDecifradoBytes); // Calcular HMAC localmente
                
                //Verificar HMAC 
                
                if(Algoritmos.verificar(hmacRecibidoBytes, hmacCalculado)) { // Verificar HMAC
                    escritor.println("OK"); // Enviar OK al servidor
                } else {
                    System.out.println("HMAC 3 incorrecto"); // Imprimir HMAC incorrecto
                    escritor.println("ERROR"); // Enviar ERROR al servidor
                    return; // Terminar el hilo si hay error
                } 

            }
            catch (Exception e) {
                e.printStackTrace(); // Manejar excepciones
            }
            
            
            // Se cierran flujos y socket
            lector.close();
            escritor.close();
            socket.close();

            System.out.println("Cliente " + idCli + " desconectado"); // Imprimir cliente desconectado

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Error al conectar el cliente: " + idCli + ":" + e.getMessage()); // Imprimir error de conexión
        } 
    } 
}
