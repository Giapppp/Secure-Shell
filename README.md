# Secure Shell Protocol: Introduction and Some Cryptographic Attacks

## Abstract
In this project, we will delve into the world of Secure Shell (SSH), a widely used cryptographic network protocol for secure remote access to systems and secure file transfers. We will begin with an introduction to SSH, exploring its key features and benefits. We will also discuss the fundamental principles of SSH cryptography and how it ensures secure communication between client and server. Furthermore, we will examine some common cryptographic attacks that can potentially compromise the security of SSH implementations, focus mainly on Golang intepreter. 

## Introduction to SSH

- The Secure-SHell-Protocol (SSH) is used to administer Unix-based servers, including virtual cloud servers. Other use cases include port forwarding and X11 forwarding. This project will introduce about history of SSH and how to use it

#### Shell

- A Shell provides you with an interface to the Unix system. It gathers input from you and executes programs based on that input. When a program finishes executing, it displays that program's output.

![Ubuntu Linux Bash Shell.](https://github.com/Giapppp/Secure-Shell/blob/main/images/ssh1.png)

- A **<em>remote shell</em>** [1] is a tool for executing commands on a device through a command-line shell (a program enabling computer control through commands) on another.
- Remote shell functionality first appeared in 1983 in the BSD operating system. It was later implemented in other operating systems, among them Windows. Both built-in system tools and standalone utilities can be used as a remote shell. Shells on remote computers could also be accessed via **<em>telnet</em>** [2]. Due to severe security problems, both variants were replaced by SSH

#### SSH

- SSH was first designed in 1995 by Finnish computer scientist Tatu Ylönen
- SSH is a cryptographic network protocol for operating network services securely over an unsecured network. Its most notable applications are remote login and command-line execution.
-  SSH is a versatile combination of algorithm and key negotiation (SSH Key Exchange) as well as encryption and authentication of data (SSH Binary Packet Protocol). SSH can thus be used to secure remote command input via Telnet, rlogin, rsh, rexec, or the SSH connection protocol and file transfers via SFTP or Secure Copy (SCP)

![Dialog on the first login with SSH](https://github.com/Giapppp/Secure-Shell/blob/main/images/ssh2.png)

#### History of SSH

- SSH-1: The version of SSH published by Tatu Ylönen in 1995 is known as SSH-1 or version 1.x. The original implementation was released as freeware in July 1995. In December of the same year, Ylönen founded SSH Communications Security to market SSH-1 as a product.

<p align="center" width="100%">
    <img width="100%" src="https://github.com/Giapppp/Secure-Shell/blob/main/images/Screenshot%202023-11-10%20214216.png">
    SSH-1 Handshake<br>
</p>

- OpenSSH: In 1999, some developers decided to create an open-source SSH variant from version 1.2.12 of the original program. Initially, this became OSSH, and eventually, under the direction of the OpenBSD team, OpenSSH. OpenSSH now only supports version 2.0.


- SSH 2.0: Version 2.0 of SSH is a complete redesign of the SSH protocol. The architecture of SSH 2.0 is described in RFC 4251 [3]. 

<p align="center" width="100%">
    <img width="100%" src="https://github.com/Giapppp/Secure-Shell/blob/main/images/ssh_0304.gif">
    SSH 2.0<br>
</p>

## Application Scenarios

- Golang developers want to replace a secure SSH than default ones in Linux, so they decide to make another one by Golang
- They use crypto/ssh library in Golang to build SSH server to listen and connect, but they don't know some weakness in the library
- Hacker know the weakness and attack

## Proposed Solution

### [CVE-2022-27191](https://nvd.nist.gov/vuln/detail/CVE-2022-27191)
- Vulnerable: The golang.org/x/crypto/ssh package before 0.0.0-20220314234659-1baeb1ce4c0b for Go allows an attacker to crash a server in certain circumstances involving AddHostKey.

- Detailed:
    
    An attacker could cause a crash in a golang.org/x/crypto/ssh server under these conditions:

    - The server has been configured by passing a [Signer](https://pkg.go.dev/golang.org/x/crypto/ssh#Signer) to [ServerConfig.AddHostKey](https://pkg.go.dev/golang.org/x/crypto/ssh#ServerConfig.AddHostKey).

    - The Signer passed to AddHostKey does not also implement [AlgorithmSigner](https://pkg.go.dev/golang.org/x/crypto/ssh#AlgorithmSigner).

    - The Signer passed to AddHostKey does return a key of type “ssh-rsa” from its PublicKey method.

    Servers that only use Signer implementations provided by the ssh package are unaffected

    - POC

- Fix: Golang Version v0.0.0-20220315160706-3147a52a75dd was released to fix this bug

### [CVE-2021-43565](https://nvd.nist.gov/vuln/detail/CVE-2021-43565)

- Vulnerable: The x/crypto/ssh package before 0.0.0-20211202192323-5770296d904e of golang.org/x/crypto allows an attacker to panic an SSH server.

- Detailed:
    - This issue was discovered and reported by Rod Hynes, Psiphon Inc.

    - When using AES-GCM or ChaCha20Poly1305, consuming a malformed packet which contains empty plaintext causes a panic, due to the assumption that there will always be at least one byte, containing the number of padding bytes.

    - Therefore, it allowed unauthenticated clients to cause a panic in SSH servers

    - POC

- Fix: Golang released version v0.0.0-20211202192323-5770296d904e of golang.org/x/crypto to fix this bug

### [CVE-2020-9283](https://nvd.nist.gov/vuln/detail/CVE-2020-9283)

- Vulnerable: golang.org/x/crypto before v0.0.0-20200220183623-bac4c82f6975 for Go allows a panic during signature verification in the golang.org/x/crypto/ssh package. A client can attack an SSH server that accepts public keys. Also, a server can attack any SSH client.

- Detailed: 

    - An attacker can craft an ssh-ed25519 or sk-ssh-ed25519@openssh.com public key, such that the library will panic when trying to verify a signature with it. Clients can deliver such a public key and signature to any golang.org/x/crypto/ssh server with a PublicKeyCallback, and servers can deliver them to any golang.org/x/crypto/ssh client.

    - This issue was discovered and reported by Alex Gaynor, Fish in a Barrel

    - POC (with Writeup): https://dev.to/brompwnie/modifying-go-s-crypto-ssh-library-for-cve-2020-9283-26a7

- Fix: For Debian 9 stretch, these problems have been fixed in version 1:0.0\~git20170407.0.55a552f+REALLY.0.0\~git20161012.0.5f31782-1+deb8u1.

## References

[1]. Kantor, B.: BSD Rlogin. RFC 1282 (Informational) (1991). DOI 10.17487/RFC1282. URL
https://www.rfc-editor.org/rfc/rfc1282.txt

[2]. Postel, J., Reynolds, J.: Telnet Protocol Specification. RFC 854 (Internet Standard) (1983). DOI
10.17487/RFC0854. URL https://www.rfc-editor.org/rfc/rfc854.txt. Updated by
RFC 5198

[3]. Ylonen, T., Lonvick (Ed.), C.: The Secure Shell (SSH) Protocol Architecture. RFC 4251
(Proposed Standard) (2006). DOI 10.17487/RFC4251. URL https://www.rfc-editor.org/rfc/rfc4251.txt. Updated by RFCs 8308, 9141
