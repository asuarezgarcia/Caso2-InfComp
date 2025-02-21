import java.io.*;

public class ProtocoloServidor {
    // observe que es un método estático.
    // observe que lanza excepciones de tipo IOException
    public static void procesar(BufferedReader pIn, PrintWriter pOut)
            throws IOException {
        String inputLine;
        String outputLine;

        // lee del flujo de entrada
        inputLine = pIn.readLine();
        System.out.println("Entrada a procesar: " + inputLine);

        // procesa la entrada
        outputLine = inputLine;

        // escribe en el flujo de salida
        pOut.println(outputLine);
        System.out.println("Salida procesada: " + outputLine);
    }
}
