package Caso2.Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import Caso2.Servidor.Algoritmos;


public class Cliente {
    public static final int PUERTO = 3400; 
    public static final String SERVIDOR = "localhost"; 
    static PublicKey llavePublica = null; // Guarda llave pública del servidor
    
        @SuppressWarnings("resource")
        public static void main(String args[]) throws Exception {
            Socket socket = null; 
            PrintWriter escritor = null; 
            BufferedReader lector = null; 
            System.out.println("Cliente iniciado"); 
            try {
               //crear el socket en el lado del cliente
                socket = new Socket(SERVIDOR, PUERTO); 
                //crear el flujo de salida
                escritor = new PrintWriter(socket.getOutputStream(), true); 
                //crear el flujo de entrada
                lector = new BufferedReader(new java.io.InputStreamReader(socket.getInputStream()));   
                //0b leer llave publica del servidor en el archivo 
                try {
                    llavePublica = Algoritmos.leerLlavePublica("llavePublica.key");
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace(); 
                throw new RuntimeException("Error al leer la llave pública del servidor", e);
            } 
            // Genero el reto numero aleatorio y lo mando 
            SecureRandom random = new SecureRandom();
            int reto = random.nextInt(10000); // Número aleatorio entre 0 y 9999  
            String retoString = String.valueOf(reto); // Convertir el número a cadena
            escritor.println(retoString); // Enviar el reto al servidor 
            // Decifrar respuesta con la llave publica del servidor (R) y verificar de que eso sea igual al reto, si esta bien mando OK o ERROR 
            byte [] decifrado = Algoritmos.RSA(llavePublica, String.valueOf(reto).getBytes(), false); // Decifrar el reto con la llave pública  

            if (Algoritmos.verificar(decifrado, retoString.getBytes())) { // Verificar si el reto coincide
                escritor.println("OK"); // Enviar OK al servidor
            } else {
                escritor.println("ERROR"); // Enviar ERROR al servidor
            }
            //Recibo G,P,G^x Y la firma(HAY TENEMOS PROBLEMAS PQ USO LLAVE PRIVADA DEL SERVIDOR) 
            //Si eso esta bien, OK o ERROR
            //Calculo (G^x)^y
            String gx = lector.readLine(); // Leer G^x 
            byte[] gxB = Base64.getDecoder().decode(gx); // Decodificar G^x 
            PublicKey llaveServidor = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(gxB)); // Generar llave pública del servidor 
            //PrivateKey llavePrivadaServidor = KeyFactory.getInstance("DH").generatePrivate(new X509EncodedKeySpec(gxB)); // Generar llave privada del servidor
            //genero llave simetrica para cifrar K_AB1
            //genero llave simetrica para MAC K_AB2
            //Generar IV(Preguntar nuevamente q es el IV) 
            //Decifrar encriptacion de tabla de servicios
            //Verificar el HMAC 
            // Si HMAC esta bien, Cifro respuesta de eleccion y envio el HMAC 
            //Cuando me den la ip y el puerto, verifico HMAC y desencripto la respuesta del servidor , si esta bien OK o ERROR
        } catch (Exception e) {
            e.printStackTrace(); 
            System.exit(-1);
        } 
        //crear un flujo para leer lo que escribe el cliente por el teclado 
        BufferedReader stdIn = new BufferedReader(new java.io.InputStreamReader(System.in)); 
        //Se ejecuta el protocolo de comunicación 
        ProtocoloCliente.procesar(stdIn, lector, escritor);
        // cerrar flujos y socket
        stdIn.close(); 
        escritor.close();
        lector.close();
        socket.close();
    }
}
