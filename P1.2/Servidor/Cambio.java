int numeroThreads = 0;

while (continuar) {
    // crear el socket
    Socket socket = ss.accept();

    // crear el thread con el socket y el id
    ThreadServidor thread = new ThreadServidor(socket, numeroThreads);
    numeroThreads++;

    // start
    thread.start();
}
ss.close();