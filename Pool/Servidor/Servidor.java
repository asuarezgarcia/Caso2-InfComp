public static void main(String args[]) throws IOException {

    int N_THREADS = 10;

    final ExecutorService pool = Executors.newFixedThreadPool(N_THREADS);

    ServerSocket servSock = null;
    try {
        servSock = new ServerSocket(PUERTO);
        System.out.println("Listo para recibir conexiones");
        while (true) {
            Socket cliente = servSock.accept();

            pool.execute(new ProtocoloServidor(cliente));
        }
    } catch (Exception e) {
        System.err.println("Ocurrió un error");
        e.printStackTrace();
    } finally {
        try {
            servSock.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
