package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

// Aquí se maneja cada conexión de cliente en un hilo separado.
// Se manejan los enviós y recepciones del orden de diferentes mensajes
// y se llaman a las diferentes clases que encriptan
public class ThreadServPrincipal extends Thread {
    
    // Atributos
    private Socket sktCli = null;
    private int id; // Atributo para identificar el thread

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
            
            // Paso 2b y 3: Recibir reto (número aleatorio) y calcular ruta

            // Paso 4: Enviar ruta al cliente

            // Paso 7: Si recibe error, terminar, si es OK, generar G, P, G^x, y F(K_w-, (G, P, G^x))

            // Paso 11b: Recibe G^y, luego calcula (G^y)^x 
            
            // Paso 11b.2: calcula llave simétrica para cifrar K_AB1 y MAC K_AB2
            
            // Paso 13: Envía C(K_AB1, tabla_ids_servicios) y HMAC(MAC K_AB2, tabla_ids_servicios)

            // Paso 15: Verifica HMAC; recibe C(K_AB1, id_servicio + ip_cliente) y HMAC(K_AB2, id_servicio + ip_cliente)

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
