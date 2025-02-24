public static void main(String args[]) throws IOException {
    ServerSocket ss = null;
    boolean continuar = true;
    int numeroThreads = 0; // Variable para controlar los identificadores de los threads

    System.out.println("Main Server ...");

    try {
        ss = new ServerSocket(3400); // Número de puerto
    } catch (IOException e) {
        System.err.println("No se pudo crear el socket en el puerto: " + 3400);
        System.exit(-1);
    }

    while (continuar) {
        // crear el thread y lanzarlo.

        // crear el socket
        Socket socket = ss.accept();

        // crear el thread con el socket y el id
        ThreadServidor thread = new ThreadServidor(socket, numeroThreads);
        numeroThreads++; // Asegurar que cada thread tenga un identificador diferente

        // start
        thread.start();
    }
    ss.close();
}
