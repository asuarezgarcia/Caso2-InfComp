package Caso2.Servidor;

import java.security.AlgorithmParameterGenerator;

public class Algoritmos {

    //Atributos

    //Métodos

    // DiffieHellman; numeros primos mayores a 1024 bits = 128 bytes 
    public int DiffieHellman1(int P, int G, int X) {
        // Generar y
        int Y = (int) Math.pow(G, X) % P; // G^X mod P
        return Y;
    }

    public int DiffieHellman2(int P, int Y, int X) {
        // Calcular llave final
        int K = (int) Math.pow(Y, X) % P; // Y^X mod P
        return K;
    }
    
}
