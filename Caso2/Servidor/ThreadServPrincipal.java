package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;


import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.security.spec.*;
import javax.crypto.*;
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
    private SecretKey llaveSimetrica = null; // Guarda llave simétrica AES
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
            
            // Paso 2b, 3 y 4: Recibir reto (número aleatorio), calcular ruta con Rta con RSA y enviarlo
            String reto = lector.readLine(); // Leer reto
            byte[] Rta = Algoritmos.RSA(llavePrivada, reto.getBytes(), true); // Cifrar el reto con la llave privada
            escritor.println(new String(Rta)); // Enviar el reto cifrado al cliente

            // Paso 7: Si recibe error, terminar, si es OK, generar G, P, G^x, y F(K_w-, (G, P, G^x)) con DiffieHellman1
            if (lector.readLine().equals("Error")) {
                System.out.println("Error en la conexión, cerrando el hilo.");
                return; // Terminar el hilo si hay error
            }
            else {
                try {
                    // Obtener llaves con DH1
                    KeyPair parLlaves = Algoritmos.DiffieHellman1(); // Generar par de llaves
                    PublicKey dhPublica = parLlaves.getPublic(); // Obtener llave pública
                    PrivateKey dhPrivada = parLlaves.getPrivate(); // Obtener llave privada

                    // Guardar llaves DH en atributo
                    this.parLlavesDH = parLlaves; 
                    
                    // Mandar llave pública al cliente
                    String publicaBase64 = Base64.getEncoder().encodeToString(dhPublica.getEncoded()); // Codificar llave pública en Base64
                    escritor.println(publicaBase64); // Enviar llave pública al cliente

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            // Paso 11b: Recibe G^y, luego calcula (G^y)^x con DiffieHellman2
            String gY = lector.readLine(); // Leer G^y del cliente
            byte[] gYBytes = Base64.getDecoder().decode(gY); // Decodificar G^y de Base64

            String IV = lector.readLine(); // Leer IV del cliente
            byte[] ivBytes = Base64.getDecoder().decode(IV); // Decodificar IV de Base64
            this.iv = new IvParameterSpec(ivBytes);


            try{
                PublicKey llPublicaRecibida = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(gYBytes)); // Generar llave pública DH
                PrivateKey llPriv = parLlavesDH.getPrivate(); // Obtener llave privada DH 
                SecretKey llaveSimetrica = Algoritmos.DiffieHellman2( llPriv, llPublicaRecibida); // Calcular llave simétrica 
                this.llaveSimetrica = llaveSimetrica; // Guardar llave simétrica en atributo

            } catch (Exception e) {
                e.printStackTrace();
            }
            
            // Paso 11b.2: calcula  K_AB1 y MAC K_AB2 con digest y hmac
            try {
                byte[] llaveSimetricaBytes = llaveSimetrica.getEncoded(); // Obtener bytes de la llave simétrica
                byte[] resultDigest = Algoritmos.Digest(llaveSimetricaBytes); // Calcular K_AB1 con digest
                // Guardamos K_AB1 y K_AB2
                byte[] KAB1 = new byte[resultDigest.length / 2];
                for (int i = 0; i < resultDigest.length / 2; i++) {
                    KAB1[i] = resultDigest[i]; // Guardar K_AB1
                    K_AB2[i] = resultDigest[i + (resultDigest.length / 2)]; // Guardar K_AB2
                }
                this.K_AB1 = new SecretKeySpec(KAB1, 0, KAB1.length, "AES");

            } catch (Exception e) {
                e.printStackTrace();
            }
            
            // Paso 13: Cifrar y enviar C(K_AB1, tabla_ids_servicios) y HMAC(MAC K_AB2, tabla_ids_servicios)

            ArrayList<ArrayList<String>> servidores = ServPrincipal.getTablaServidores(); // Obtener tabla de servidores
            ArrayList<String> tablaIdsServicios = new ArrayList<>(); 
            for (int i = 0; i < servidores.size(); i++) {
                tablaIdsServicios.add(servidores.get(i).get(0)); // Agregar id de servicio a la tabla
            }
            
            for (int i = 0; i < tablaIdsServicios.size(); i++) {
                String idServicio = tablaIdsServicios.get(i); // Obtener id de servicio
                byte[] cifrado = Algoritmos.AES(K_AB1, idServicio, iv, true); // Cifrar id de servicio con AES
                escritor.println(Base64.getEncoder().encodeToString(cifrado)); // Enviar id de servicio cifrado al cliente

                byte[] idServicioBytes = idServicio.getBytes(); // Obtener bytes del id de servicio
                try {
                    byte[] hmac = Algoritmos.calculoHMac(K_AB2, idServicioBytes); // Calcular HMAC del id de servicio
                    escritor.println(Base64.getEncoder().encodeToString(hmac)); // Enviar HMAC al cliente
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new RuntimeException("Error al calcular HMAC del id de servicio", e);
                }
            }

            // Paso 15: Verifica HMAC; recibe C(K_AB1, id_servicio + ip_cliente) y HMAC(K_AB2, id_servicio + ip_cliente)
            String idServicioCifrado = lector.readLine(); // Leer id de servicio 
            byte[] idServicioDecifrado = Algoritmos.AES(K_AB1, idServicioCifrado, iv, false); // Descifrar id de servicio
            String buscado = new String(idServicioDecifrado); // Convertir bytes a string

                //Verificar HMAC
            String hmacRecibido = lector.readLine(); // Leer HMAC recibido
            byte[] hmacRecibidoBytes = Base64.getDecoder().decode(hmacRecibido); // Decodificar HMAC recibido
            if(Algoritmos.verificar(hmacRecibidoBytes, K_AB2)) { // Verificar HMAC
                System.out.println("HMAC correcto"); // Imprimir HMAC correcto 
            } else {
                System.out.println("HMAC incorrecto"); // Imprimir HMAC incorrecto #TODO debería haber algo que termine la sesión
            }

            for (int j = 0; j < servidores.size(); j++) { // Buscamos en la tabla de servicios completa
                if (servidores.get(j).get(0).equals(buscado)) { // Hallar servicio buscado
                    String ipServidor = servidores.get(j).get(2); // Obtener ip del servidor
                    String puertoServidor = servidores.get(j).get(3); // Obtener puerto del servidor

                    byte [] ipCifrado = Algoritmos.AES(K_AB1, ipServidor, iv, true); // Cifrar ip
                    byte [] puertoCifrado = Algoritmos.AES(K_AB1, puertoServidor, iv, true); // Cifrar puerto

                    escritor.println(Base64.getEncoder().encodeToString(ipCifrado)); // Enviar ip cifrada al cliente
                    escritor.println(Base64.getEncoder().encodeToString(puertoCifrado)); // Enviar puerto cifrado al cliente
                    System.out.println("Id de servicio correcto: " + buscado); // Imprimir id de servicio correcto
                    break;
                }    
                break;
            }
            // Paso 16: Envía C(K_AB1, ip_servidor + puerto_servidor) y HMAC(K_AB2, ip_servidor + puerto_servidor)

            // Final: recibe "Ok" o "Error" y termina el hilo


            // se ejecuta el protocolo en el lado servidor
            ProtocoloServPrincipal.procesar(lector, escritor);







            // se cierran flujos y socket
            lector.close();
            escritor.close();
            sktCli.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
