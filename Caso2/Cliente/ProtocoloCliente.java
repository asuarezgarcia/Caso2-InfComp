package Caso2.Cliente;

import java.io.BufferedReader;
import java.io.PrintWriter;

public class ProtocoloCliente {
    public static void procesar (BufferedReader stdIn, BufferedReader lector, PrintWriter escritor) throws Exception {
        String fromServer;
        String fromUser;

        boolean ejecutar = true;
        //se ejecuta el protocolo de comunicación
        while (ejecutar) {
            //enviar al servidor
            System.out.print("Mensaje para enviar: ");
            fromUser = stdIn.readLine(); 

            if(fromUser != null){ 
                System.out.println("Cliente: " + fromUser); 
                if(fromUser.equalsIgnoreCase("OK")){ 
                    System.out.println("Cliente: Fin de la comunicación"); 
                    ejecutar = false; 
                } else {
                    escritor.println(fromUser); //enviar al servidor
                }
            }
            if((fromServer = lector.readLine()) != null){ 
                System.out.println("Servidor: " + fromServer); 
            }
        }

    }
}
