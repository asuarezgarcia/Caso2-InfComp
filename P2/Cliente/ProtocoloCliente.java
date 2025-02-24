public class ProtocoloCliente {
    public static void procesar(BufferedReader stdIn, BufferedReader pIn,
                                PrintWriter pOut) throws IOException {

        String fromServer;
        String fromUser;

        boolean ejecutar = true;

        while (ejecutar) {
            // lee del teclado
            System.out.println("Escriba el mensaje para enviar: ");
            fromUser = stdIn.readLine();

            // si lo que ingresa el usuario no es null
            if (fromUser != null) {
                System.out.println("El usuario escribió: " + fromUser);
                // si lo que ingresa el usuario es "OK"
                if (fromUser.equalsIgnoreCase("OK")) {
                    ejecutar = false;
                }

                // envía por la red
                pOut.println(fromUser);
            }

            // lee lo que llega por la red
            // si lo que llega del servidor no es null
            // observe la asignación luego la condición
            if ((fromServer = pIn.readLine()) != null) {
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
        }
    }
}
