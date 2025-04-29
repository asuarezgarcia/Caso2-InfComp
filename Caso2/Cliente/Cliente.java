package Caso2.Cliente;

import java.net.Socket;
import java.util.Random;


public class Cliente {
    public static int PUERTO = 3400; 
    public static String SERVIDOR = "localhost"; 

    public static void main(String args[]) throws Exception {
        
        // Variables para el cliente
        Socket socket = null; 
        int idCli = 1; // Contador para los hilos

        int numCli = 4; // #TODO este número se cambia para probar el cliente con diferentes números de clientes
        int secuencias = 1; // #TODO este número se cambia para probar secuencialmente

        /* TODO notas de cómo correr los escenarios
        "numCli" es la cantidad de clientes que corre AL TIEMPO; para probar los casos del escenario 2, se modifica este valore y "secuencias" queda en 1
        "secuencias" es para probar secuenciasl; para probar el escenario 1, se pone "numCli" en 1 y "secuencias" en 32 (las 32 secuencias del escenario 1)
        */
        
        try {
            for(int j = 0; j < secuencias; j++) {
                //crear el socket en el lado del cliente
                for (int i = 0; i < numCli; i++) {
                    socket = new Socket(SERVIDOR, PUERTO); 
                    Random rand = new Random(100); // Generar un número aleatorio
                    String ipCliente = String.valueOf(rand.nextInt(100)); // IP del cliente (número aleatorio entre 0 y 100)
                    new ThreadCliente(socket, ipCliente, idCli).start(); // Crear un nuevo hilo para manejar al cliente
                    idCli ++;      
                    System.out.println("Cliente" + idCli + " conectado"); 
                }
            }
        } catch (Exception e) {
            e.printStackTrace(); 
            System.err.println("Error al conectar el cliente: " + e.getMessage());
        } 
    }
}
