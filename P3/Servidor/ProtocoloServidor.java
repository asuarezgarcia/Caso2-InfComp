public static void procesar(BufferedReader pIn, PrintWriter pOut)
        throws IOException {
    String inputLine;
    String outputLine;
    int estado = 0;

    while (estado < 3 && (inputLine = pIn.readLine()) != null) {

        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0:
                if (inputLine.equalsIgnoreCase("Hola")) {
                    outputLine = "Listo";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba Hola";
                    estado = 0;
                }
                break;

            case 1:
                try {
                    int val = Integer.parseInt(inputLine);
                    val--;
                    outputLine = "" + val;
                    estado++;
                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    estado = 0;
                }
                break;

            case 2:
                if (inputLine.equalsIgnoreCase("OK")) {
                    outputLine = "ADIOS";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba OK";
                    estado = 0;
                }
                break;

            default:
                outputLine = "ERROR";
                estado = 0;
        }
        pOut.println(outputLine);
    }
}
