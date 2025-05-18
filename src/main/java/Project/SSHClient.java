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
    private static final int SERVER_PORT = 22226;
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

    private static void interactiveConnection() {
        System.out.println("\n=== Interactive SSH Connection ===");

        try {
            Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            Map<String, Object> identification = (Map<String, Object>) in.readObject();
            System.out.println("\nServer identification received:");
            System.out.println("Server ID: " + identification.get("server_id"));

            Map<String, List<String>> algorithms = (Map<String, List<String>>) identification.get("supported_algorithms");

            System.out.println("\nAvailable algorithms:");
            for (Map.Entry<String, List<String>> entry : algorithms.entrySet()) {
                System.out.println(entry.getKey() + ": " + entry.getValue());
            }

            System.out.print("\nPress Enter to continue...");
            scanner.nextLine();
            scanner.nextLine();

            System.out.println("\n=== Key Exchange ===");
            System.out.println("Performing Diffie-Hellman key exchange...");
            byte[] sharedSecret = performKeyExchange(out, in, true);

            System.out.println("\n=== Server Authentication ===");
            System.out.println("Verifying server identity...");
            verifyServerAuthentication(in, sharedSecret, true);

            System.out.println("\n=== Session Key Generation ===");
            System.out.println("Deriving session keys...");
            generateSessionKeys(in, sharedSecret, true);

            System.out.println("\n=== Connection Established ===");
            System.out.println("1. Start secure shell session");
            System.out.println("2. Disconnect");
            System.out.print("Enter choice: ");
            String finalChoice = scanner.nextLine();

            if (finalChoice.equals("1")) {
                System.out.println("\nStarting secure session... (simulated)");
                System.out.println("Type 'exit' to end the session");

                while (true) {
                    System.out.print("ssh> ");
                    String input = scanner.nextLine();
                    if (input.equalsIgnoreCase("exit")) {
                        break;
                    }
                    System.out.println("Command executed: " + input);
                }
            }

            System.out.println("Disconnecting...");
            socket.close();
        } catch (Exception e) {
            System.err.println("Connection failed: " + e.getMessage());
        }
    }

    private static byte[] performKeyExchange(ObjectOutputStream out, ObjectInputStream in, boolean verbose) throws Exception {
            PublicKey serverDhPublicKey = (PublicKey) in.readObject();
            if (verbose) {
                System.out.println("Server DH Public Key: " + Base64.getEncoder().encodeToString(serverDhPublicKey.getEncoded()));
            }

            DHPublicKey dhPubKey = (DHPublicKey) serverDhPublicKey;
            DHParameterSpec dhParams = dhPubKey.getParams();

            KeyPairGenerator dhKpairGen = KeyPairGenerator.getInstance("DH");
            dhKpairGen.initialize(dhParams);
            KeyPair dhKeyPair = dhKpairGen.generateKeyPair();

            out.writeObject(dhKeyPair.getPublic());
            out.flush();

            if (verbose) {
                System.out.println("Client DH Public Key: " + Base64.getEncoder().encodeToString(dhKeyPair.getPublic().getEncoded()));
            }

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(dhKeyPair.getPrivate());
            keyAgreement.doPhase(serverDhPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();

            if (verbose) {
                System.out.println("Shared Secret (DH): " + Base64.getEncoder().encodeToString(sharedSecret));
                System.out.println("Key exchange completed successfully");
            }

            return sharedSecret;
        }

    private static void verifyServerAuthentication(ObjectInputStream in, byte[] sharedSecret, boolean verbose) throws Exception {
            Map<String, Object> authData = (Map<String, Object>) in.readObject();
            PublicKey serverPublicKey = (PublicKey) authData.get("public_key");
            byte[] signature = (byte[]) authData.get("signature");

            if (verbose) {
                System.out.println("Server RSA Public Key: " + Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));
            }

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(serverPublicKey);
            verifier.update(sharedSecret);

            if (verifier.verify(signature)) {
                if (verbose) {
                    System.out.println("Server identity verified successfully");
                }
            } else {
                throw new SecurityException("Server authentication failed");
            }
        }

    private static void generateSessionKeys(ObjectInputStream in, byte[] sharedSecret, boolean verbose) throws Exception {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] prk = digest.digest(sharedSecret);

            if (verbose) {
                System.out.println("PRK (SHA-256 of shared secret): " + Base64.getEncoder().encodeToString(prk));
            }

            byte[] info = "session keys".getBytes();
            byte[] okm = new byte[32];

            byte[] t = new byte[0];
            int remaining = okm.length;
            int offset = 0;

            for (int i = 1; remaining > 0; i++) {
                digest.reset();
                digest.update(t);
                digest.update(info);
                digest.update((byte) i);
                t = digest.digest();

                int toCopy = Math.min(t.length, remaining);
                System.arraycopy(t, 0, okm, offset, toCopy);
                offset += toCopy;
                remaining -= toCopy;
            }

            if (verbose) {
                System.out.println("Derived Session Key (OKM): " + Base64.getEncoder().encodeToString(okm));
                System.out.println("Session keys generated successfully");
            }

            String confirmation = (String) in.readObject();
            if (!"Session keys established".equals(confirmation)) {
                throw new Exception("Session key establishment failed");
            }
        }
}


