public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    public static void main(String args[]) throws IOException {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;

        System.out.println("Cliente ...");

        try {
            socket = new Socket(SERVIDOR, PUERTO);

            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        } catch (IOException e) {
            System.err.println("Exception: " + e.getMessage());
            System.exit(1);
        }

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        // se ejecuta el protocolo en el lado cliente
        ProtocoloCliente.procesar(stdIn, lector, escritor);

        escritor.close();
        lector.close();
        socket.close();
        stdIn.close();
    }
}

