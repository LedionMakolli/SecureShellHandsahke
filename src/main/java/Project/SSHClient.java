package Project;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Scanner;

public class SSHClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 2222;
    private static boolean interactiveMode = false;
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("Welcome to Simplified SSH Client.");

        // Perdoruesi zgjedh mode-in
        System.out.println("\nChoose connection mode:");
        System.out.println("1. Direct connection (minimal output)");
        System.out.println("2. Interactive connection (make choices)");
        System.out.print("Enter choice (1 or 2): ");

        int choice = scanner.nextInt();
        interactiveMode = (choice == 2);

        if (!interactiveMode) {
            directConnection();
        } else {
            interactiveConnection();
        }

        scanner.close();
    }

    private static void directConnection() {
        System.out.println("\nAttempting to connect to the SSH server...");

        try {
            Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            System.out.println("Starting handshake protocol...");

            // Kalimi i detajeve identifikuese ne modin direct
            in.readObject();

            byte[] sharedSecret = performKeyExchange(out, in, false);
            verifyServerAuthentication(in, sharedSecret, false);
            generateSessionKeys(in, sharedSecret, false);

            System.out.println("Server identity verified. Handshake successful.");
            System.out.println("Secure channel established. You can now begin your session.");

            socket.close();
        } catch (Exception e) {
            System.err.println("Connection failed: " + e.getMessage());
        }
    }
}
