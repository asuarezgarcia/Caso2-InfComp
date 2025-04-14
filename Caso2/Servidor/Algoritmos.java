package Caso2.Servidor;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Algoritmos {

    //Métodos

    //RSA
    // Generar par de llaves RSA (pública y privada) de 1024 bits
    public static void generarLlavesRSA() {
        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA"); // Generador de llaves RSA
            generador.initialize(1024); // Inicializar con 1024 bits
            KeyPair parLlaves = generador.generateKeyPair(); // Retornar el par de llaves (pública y privada)

            // Obtener llaves pública y privada
            PublicKey llavePublica = parLlaves.getPublic();
            PrivateKey llavePrivada = parLlaves.getPrivate();

            // Guardar llave pública en un archivo
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("llavePublica.key"))) {
                oos.writeObject(llavePublica);
            }

            // Guardar llave privada en un archivo
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("llavePrivada.key"))) {
                oos.writeObject(llavePrivada);
            }

            System.out.println("Llaves RSA generadas y guardadas en archivos.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Lector llave pública
    public static PublicKey leerLlavePublica(String archivo) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(archivo))) {
            return (PublicKey) ois.readObject(); // Leer la llave pública del archivo
        }
    }

    // Lector llave privada
    public static PrivateKey leerLlavePrivada(String archivo) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(archivo))) {
            return (PrivateKey) ois.readObject(); // Leer la llave privada del archivo
        }
    }

    //RSA cifrar y descifrar
    public static byte[] RSA(Key llave, byte[] datos, boolean encrypt) { // el "reto" se recibe en bytes; es "datos"
        byte [] textoCifrado = null; // Inicializar el texto cifrado

        try {
            // Crear un objeto Cipher para el algoritmo RSA
            String RSA = "RSA/ECB/PKCS1Padding"; // Algoritmo de cifrado RSA con relleno PKCS#1 v1.5
            Cipher cifrador = Cipher.getInstance(RSA);

            if (encrypt) {
                cifrador.init(Cipher.ENCRYPT_MODE, llave); // Inicializar el cifrador en modo de cifrado
                textoCifrado = cifrador.doFinal(datos); // Cifrar el texto claro
            } else {
                cifrador.init(Cipher.DECRYPT_MODE, llave); // Inicializar el cifrador en modo de descifrado
                textoCifrado = cifrador.doFinal(datos); // Descifrar el texto claro
            }

            return textoCifrado; // Retornar el texto cifrado o claro

        } catch (Exception e) {
            e.printStackTrace();
            return null; // Retornar null en caso de error
        }
    }


    // Diffie-Hellman
    // Parte 1
    public static int DiffieHellman1(int P, int G, int X) {
        // Generar número aleatorio X (secreto) entre 1 y P-1
        

        // Generar y
        int Y = (int) Math.pow(G, X) % P; // G^X mod P
        return Y;
    }

    // Parte 2
    public static int DiffieHellman2(int P, int Y, int X) {
        // Calcular llave final
        int K = (int) Math.pow(Y, X) % P; // Y^X mod P
        return K;
    }


    // AES (llave 256 bits/ 32 bytes) usando CBC (llaves de 128 bits)
    // Generar IV (vector de inicialización) de 32 bytes    
    public byte[] generarIV() {
        byte[] iv = new byte[32]; // 32 bytes para AES
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    // Cifrar o descifrar texto con AES
    public static byte[] AES(SecretKey llave, String texto, IvParameterSpec IV, boolean encrypt) { 
        byte[] textoCifrado; 
        String PADDIG = "AES/CBC/PKCS5Padding"; 

        try {
            Cipher cifrador = Cipher.getInstance(PADDIG); 
            byte[] textoClaro = texto.getBytes();

            if (encrypt) {
                cifrador.init(Cipher.ENCRYPT_MODE, llave, IV); // Cifrador en modo de cifrado
            } else {
                cifrador.init(Cipher.DECRYPT_MODE, llave, IV); // Cifrador en modo de descifrado
            }

            textoCifrado = cifrador.doFinal(textoClaro); // Cifrar o descifrar el texto claro
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Error en AES: " + e.getMessage());
            return null;
        }
    } 


    
}
