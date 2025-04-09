package Caso2.Servidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

public class ProtocoloServPrincipal {
    public static void procesar(BufferedReader lector, PrintWriter escritor) throws IOException {
        // Leer la solicitud del cliente
        String solicitud = lector.readLine(); // Ejemplo: "S1", "S2", "S3"
        System.out.println("Solicitud recibida: " + solicitud);

        // Obtener la tabla de servidores
        ArrayList<ArrayList<String>> servidores = ServPrincipal.tablaServidores();

        // Buscar el servicio solicitado
        String respuesta = "Servicio no encontrado";
        for (ArrayList<String> servidor : servidores) {
            if (servidor.get(0).equalsIgnoreCase(solicitud)) { // Comparar con el ID del servicio
                respuesta = "Servicio: " + servidor.get(1) + ", IP: " + servidor.get(2) + ", Puerto: " + servidor.get(3);
                break;
            }
        }

        // Enviar la respuesta al cliente
        escritor.println(respuesta);
        System.out.println("Respuesta enviada: " + respuesta);
    }
}
