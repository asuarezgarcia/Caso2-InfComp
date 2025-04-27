package Caso2.Cliente;

import java.net.Socket;


public class Clie {
    public static int PUERTO = 3400; 
    public static String SERVIDOR = "localhost"; 

    public static void main(String args[]) throws Exception {
        
        
        // Variables para el cliente
        Socket socket = null; 
        int idCli = 0; // Contador para los hilos
        int numCli = 1;
        
        try {
            //crear el socket en el lado del cliente
            for (int i = 0; i < numCli; i++) {
                socket = new Socket(SERVIDOR, PUERTO); 
                String ipCliente = "3"; 
                new ThreadCliente(socket, ipCliente, idCli).start(); // Crear un nuevo hilo para manejar al cliente
                idCli ++;      
                System.out.println("Cliente" + idCli + " conectado"); 
            }
        } catch (Exception e) {
            e.printStackTrace(); 
            System.err.println("Error al conectar el cliente: " + e.getMessage());
        } 

    }
}
