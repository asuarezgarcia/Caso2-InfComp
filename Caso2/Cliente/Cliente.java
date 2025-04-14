package Caso2.Cliente;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.Socket;


public class Cliente {
    public static final int PUERTO = 3400; 
    public static final String SERVIDOR = "localhost";

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
