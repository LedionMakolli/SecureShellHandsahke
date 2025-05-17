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
- Gjeneron celesat **RSA** per autentikim
- Gjeneron parametrat **Diffie-Hellman (DH)** per shkembimin e celesave
- Pret klientin dhe ekzekuton proceset:
   - Identifikimi i serverit
   - Shkembimi i celesave DH
   - Autentikimi i serverit me nenshkrim RSA
   - Gjenerimi i celesave te sesionit me **HKDF**

# SSHClient.java
- Lidhja me serverin ne menyre direkte ose interaktive
- Lexon identifikimin e serverit (nese eshte ne modalitetin interaktiv)
- Kryesn shkembimin **Diffie-Hellman (DH)** dhe verifikon nenshkrimin **RSA**
- Derivon celesin e sesionit dhe vendos kanalin e sigurt

  # Shembuj te Rezultateve te Ekzekutimit
  
![run0](https://github.com/user-attachments/assets/a2e12187-ff49-4201-b1b6-3b4680e3aee8)


![run1](https://github.com/user-attachments/assets/98d092e8-9349-498c-93e5-ad687b143d07)


![run2](https://github.com/user-attachments/assets/404db16f-50bb-4caa-981e-21bb9d638d11)


![run3](https://github.com/user-attachments/assets/14b57d09-1b3a-4c85-8f65-b6c32e07b36c)


![run4](https://github.com/user-attachments/assets/ae011b57-8ecf-4b21-9b46-0dd90e3c5efe)


![run5](https://github.com/user-attachments/assets/ed0591a7-f274-4eb0-8c04-220167aaa3fd)


![run6](https://github.com/user-attachments/assets/53066fe3-406c-4702-b181-45532ffde0b0)


![run7](https://github.com/user-attachments/assets/07bf8623-46ad-4fbf-ad0b-15cc4be428c2)









