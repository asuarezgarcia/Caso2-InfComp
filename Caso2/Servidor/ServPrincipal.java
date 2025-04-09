package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class ServPrincipal {
    public static void main(String args[]) throws IOException {
        ServerSocket ss = null;
        boolean continuar = true;
        ArrayList<ArrayList<String>> servidores = tablaServidores(); // Matriz almacena datos servidores
        int i = 0; // Contador para los hilos

        try {
            ss = new ServerSocket(puerto); // TODO: no sé cuál es el puerto del principal
            System.out.println("Servidor principal activado ...");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        while (continuar) {
            // crear el socket del servidor y espera un cliente
            Socket socket = ss.accept();
            System.out.println("Cliente conectado: " + socket.getInetAddress()); // IP de quien se conectó

            // Crear un nuevo hilo para manejar al cliente
            new ThreadServPrincipal(socket, i).start();
            i++; // Incrementar contador hilos
        }

    
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
}