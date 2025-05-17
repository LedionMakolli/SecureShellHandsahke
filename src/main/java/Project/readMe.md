# Pershkrimi i Projektit

Ky projekt simulon nje lidhje te sigurte SSH mes nje serveri dhe nje klienti duke perdorur algoritmin RSA per autentikim, Diffie-Hellman per shkembimin e celesave dhe SHA=256 per derivimin e celesave te sesionit.

# Ekzekutimi i Projektit

1.**Kompiloni te dyja klasat:**

  javac project /SSHServer.java
  javac project/SSHClient.java

2.**Startoni me pare serverin:**

  java project.SSHServer

3.**Startoni klientin:**

  java project.SSHClient

4.**Zgjidhni modalitetin e lidhjes:**

  - Lidhje direkte(output minimal)
  - Lidhje interaktive (shfaqet cdo hap)


# Pershkrimi i moduleve 

# SSHServer.java
* Gjeneron celesat RSA per autentikim
* Gjeneron parametrat DH per shkembimin e celesave
* Pret klientin dhe ekzekuton:
      - Identifikimi i serverit
      - Shkembimi i celesave DH
      - Autentikimi i serverit me nenshkrim RSA
      - Gjenerimi i celesave te sesionit me HKDF

# SSHClient.java
- Lidhja me serverin ne menyre direkte ose interaktive
- Lexon identifikimin e serverit (nese eshte ne modalitetin interaktiv)
- Kryesn shkembimin DH dhe verifikon nenshkrimin RSA
- Derivon celesin e sesionit dhe vendos kanalin e sigurt

