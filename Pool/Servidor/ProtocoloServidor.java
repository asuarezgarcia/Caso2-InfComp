public ProtocoloServidor(Socket s) {
    this.sockCliente = s;
    try {
        escritor = new PrintWriter(
            sockCliente.getOutputStream(), true);
        lector = new BufferedReader(new InputStreamReader(
            sockCliente.getInputStream()));
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public void procesar(BufferedReader pIn, PrintWriter pOut)
        throws IOException {

    // lee del flujo de entrada
    String inputLine = pIn.readLine();
    System.out.println("Entrada a procesar: " + inputLine);

    // procesa la entrada
    String outputLine = inputLine;

    // escribe en el flujo de salida
    pOut.println(outputLine);
    System.out.println("Salida procesada: " + outputLine);
}
