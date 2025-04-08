package Caso2;

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

        try {
            ss = new ServerSocket(); // TODO: no sé cuál es el puerto del principal
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        while (continuar) {
            // crear el socket en el lado servidor
            // queda bloqueado esperando a que llegue un cliente
            Socket socket = ss.accept();

            try {
                // se conectan los flujos, tanto de salida como de entrada
                PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader lector = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                // se ejecuta el protocolo en el lado servidor
                ProtocoloServPrincipal.procesar(lector, escritor);

                // se cierran los flujos y el socket
                escritor.close();
                lector.close();
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
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