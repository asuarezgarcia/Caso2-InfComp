package Caso2.Servidor;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.DHParameterSpec;

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
    // Parte 1 serv
    public static KeyPair servDiffieHellman1() throws Exception {
        // Generar parámetros
        AlgorithmParameterGenerator generador = AlgorithmParameterGenerator.getInstance("DH");
        generador.init(1024); // Tamaño de la clave en bits
        AlgorithmParameters parametros = generador.generateParameters();

        // Obtener los parámetros de Diffie-Hellman
        DHParameterSpec dhSpec = parametros.getParameterSpec(DHParameterSpec.class);

        // Generar clave privada
        KeyPairGenerator generadorLlave = KeyPairGenerator.getInstance("DH");
        generadorLlave.initialize(dhSpec);
        KeyPair parLlave = generadorLlave.generateKeyPair(); // Generar el par de llaves

        return parLlave; // Retornar la llave pública y privada
    }

    // Parte 1 cliente
    public static KeyPair clienteDiffieHellman1(BigInteger p, BigInteger g) throws Exception {

        // Crear los parámetros DH con P y G
        DHParameterSpec dhSpec = new DHParameterSpec(p, g);
        
        // Generar el par de llaves
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(dhSpec);
        KeyPair parLlavesCliente = keyPairGen.generateKeyPair();
        
        return parLlavesCliente;
    }

    // Parte 2 
    public static byte[] DiffieHellman2(PrivateKey llavePrivada, PublicKey llavePublicaRecibida) throws Exception {
        // Crear el acuerdo de claves Diffie-Hellman
        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
    
        // Inicializar el acuerdo con la llave privada propia
        acuerdo.init(llavePrivada);
    
        // Realizar la fase del acuerdo con la llave pública recibida
        acuerdo.doPhase(llavePublicaRecibida, true);

        // Generar llave simétrica
        return acuerdo.generateSecret(); 
    }

    


    // Digestion SHA-512
    public static byte[] Digest(byte[] data) {
        try{
            String algorithm = "SHA-512"; // Algoritmo de digestión SHA-512
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(data);
            return digest.digest();
        } catch (Exception e) {
            return null;
        }
    }


    // AES (llave 256 bits/ 32 bytes) usando CBC (llaves de 128 bits)
    // Generar IV (vector de inicialización) de 16 bytes    
    public static byte[] generarIV() {
        byte[] iv = new byte[16]; // 16 bytes para AES
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
    
    public static String AES_Cifrado(String mensaje, SecretKey clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clave, iv);
        byte[] cifrado = cipher.doFinal(mensaje.getBytes());
        return Base64.getEncoder().encodeToString(cifrado);
    }

    public static String AES_Decifrado(String textoCifrado, SecretKey clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, clave, iv);
        byte[] decodificado = Base64.getDecoder().decode(textoCifrado);
        byte[] descifrado = cipher.doFinal(decodificado);
        return new String(descifrado, StandardCharsets.UTF_8);
    }

    // Cifrado HMAC 
    public static byte[] calculoHMac(byte [] clave, byte[] texto) throws Exception { 
        String algoritmo = "HmacSHA256"; // Algoritmo HMAC-SHA256 
        SecretKeySpec secretKey = new SecretKeySpec(clave, algoritmo);  // Crear clave secreta
        Mac mac = Mac.getInstance(algoritmo); // Crear objeto Mac 
        mac.init(secretKey); // Inicializar el objeto Mac con la clave secreta 
        return mac.doFinal(texto); // Calcular HMAC 
    }
    


    // Verificar 2 números
    public static boolean verificar(byte[] num1, byte[] num2){
        if (num1.length != num2.length) {
            System.out.println("Números diferentes");
            return false; // Los digests no son iguales
        }
        for (int i = 0; i < num1.length; i++){
            if (num1[i] != num2[i]) {
                System.out.println("Números diferentes");
                return false; // Los digests no son iguales
            }
        }
        return true; // Los digests son iguales
    } 
    
}
