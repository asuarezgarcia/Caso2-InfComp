package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.CyclicBarrier;

public class ServPrincipal {

    public static long tiempoFirma = 0; 
    public static long tiempoCifrado = 0; 
    public static long tiempoVerificar = 0;
    public static long tiempoRSA = 0; // Tiempo total de ejecución
    private static int numClientes = 0; // Número de clientes a manejar
      

    public static void main(String args[]) throws IOException {
        
        ServerSocket ss = null;
        boolean continuar = true;
        ArrayList<ArrayList<String>> servidores = tablaServidores(); // Matriz almacena datos servidores
        int i = 0; // Contador para los hilos

        // Crear la barrera
        CyclicBarrier barrier = new CyclicBarrier(1, () -> {
            // Acción cuando todos los hilos terminen
            imprimirTiempos();
            numClientes = 0; // Reiniciar el contador de clientes
            System.out.println("Fin del servidor principal.");
        });
        

        // Generar llaves RSA
        Algoritmos.generarLlavesRSA(); 
        System.out.println("Llaves RSA generadas y guardadas en archivos.");

        try {
            ss = new ServerSocket(3400);
            ss.setSoTimeout(5000);
            System.out.println("Servidor principal activado ..." + "\n");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        while (continuar) {
            try {
                // crear el socket del servidor y espera un cliente
                Socket socket = ss.accept();

                i++; // Incrementar contador hilos
                numClientes++; // Incrementar contador clientes

                //Actualizar barrera
                barrier = new CyclicBarrier(numClientes, () -> {
                    // Acción cuando todos los hilos terminen
                    imprimirTiempos();
                    System.out.println(numClientes);
                    numClientes = 0; // Reiniciar el contador de clientes
                    System.out.println("Fin del servidor principal.");
                });

                // Crear un nuevo hilo para manejar al cliente
                new ThreadServPrincipal(socket, i, barrier).start();
                
            } catch (IOException e) {
                System.out.println("Tiempo de espera agotado. No se aceptan más conexiones.");
                continuar = false; // Salir del bucle si no hay más conexiones
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        try {
            ss.close(); // Cerrar el socket del servidor
        } catch (IOException e) {
            e.printStackTrace();
        }
    
    
    }

    // getter de la tabla de servidores
    public synchronized static ArrayList<ArrayList<String>> getTablaServidores() {
        return tablaServidores();
    }

    // Método crear matriz
    public static ArrayList<ArrayList<String>> tablaServidores(){
        ArrayList<ArrayList<String>> servidores = new ArrayList<>();

        ArrayList<String> servidor1 = new ArrayList<String>();
        servidor1.add("S1"); // Id del servidor
        servidor1.add("Servicio 1"); // Nombre del servicio
        servidor1.add("localhost"); // Dirección IP del servidor
        servidor1.add(String.valueOf(3400)); // Puerto del servidor
        servidores.add(servidor1);

        ArrayList<String> servidor2 = new ArrayList<String>();
        servidor2.add("S2"); // Id del servidor
        servidor2.add("Servicio 2"); // Nombre del servicio
        servidor2.add("localhost"); // Dirección IP del servidor
        servidor2.add(String.valueOf(3401)); // Puerto del servidor
        servidores.add(servidor2);

        ArrayList<String> servidor3 = new ArrayList<String>();
        servidor3.add("S3"); // Id del servidor
        servidor3.add("Servicio 3"); // Nombre del servicio
        servidor3.add("localhost"); // Dirección IP del servidor
        servidor3.add(String.valueOf(3402)); // Puerto del servidor
        servidores.add(servidor3);

        return servidores;
    }

    public synchronized static void imprimirTiempos() {
        System.out.println("\n" + "--------------------------------------------");
        System.out.println("Tiempo total de firma: " + tiempoFirma/numClientes + " ms");
        System.out.println("Tiempo total de cifrado llave simétrica: " + tiempoCifrado/numClientes + " ms");
        System.out.println("Tiempo total de verificación: " + tiempoVerificar/numClientes + " ms");
        System.out.println("Tiempo total de cifrado llave asimétrica: " + tiempoRSA/numClientes + " ms");
        System.out.println("--------------------------------------------" + "\n");
    }

    public synchronized static void actualizarTiempos(long tiempoFirma, long tiempoCifrado, long tiempoVerificar, long tiempoRSA) {
        ServPrincipal.tiempoFirma += tiempoFirma; // Acumular el tiempo de firma
        ServPrincipal.tiempoCifrado += tiempoCifrado; // Acumular el tiempo de cifrado
        ServPrincipal.tiempoVerificar += tiempoVerificar; // Acumular el tiempo de verificación
        ServPrincipal.tiempoRSA += tiempoRSA; // Acumular el tiempo total de cifrado y verificación
    }   

    public void setNumClientes(int numClientes) {
        ServPrincipal.numClientes = numClientes;
    }
}