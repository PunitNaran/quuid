# QuantumUUID Generation & Use Cases
(A Quantum-resistant UUID generation and hybrid cryptography with ECDSA and SPHINCS+)

## Overview

This project implements a quantum-resistant **UUID** generation function called **QuantumUUID**, leveraging hybrid cryptography and multiple rounds of hashing to ensure robustness against quantum computing threats. The generated **QuantumUUID** is designed to be highly secure, incorporating cryptographic algorithms like ECDSA, SPHINCS+, SHA3-512, and AES encryption.

In addition to the UUID itself, **QuantumUUIDMetadata** is generated to provide crucial information about the UUID's creation and cryptographic strength. This metadata can be used for auditability, compliance, and proper key management.

## Key Features

- **Quantum-Resistant**: Utilizes cryptographic algorithms that are resistant to quantum computing threats.
- **Hybrid Cryptography**: Combines ECDSA (Elliptic Curve Digital Signature Algorithm) and SPHINCS+ (a post-quantum signature scheme) for maximum security.
- **Multiple Hashing Rounds**: Uses SHA3-512, BLAKE3, and SHAKE256 to process the entropy and enhance security.
- **Metadata**: Associates essential metadata with each generated UUID for better traceability, security assurance, and version control.

## Dependencies

The application uses several Go packages. To install the dependencies, run:

```bash
go mod tidy
```

This command will install the required dependencies specified in `go.mod`.


## Building the Application

After setting up the dependencies, you can build the application using the following command:

```bash
cd cmd/
```

```bash
go build -o myapp main.go
```

This will create an executable file named `myapp` in the current directory.

## Running the Application

### Command-Line Flags

The application accepts several command-line flags:

- `-mode`: Run mode (`server`, `standalone`, `rpc`)
- `-tls-cert`: Path to the TLS certificate file (required for secure HTTPS connections)
- `-tls-key`: Path to the TLS private key file (required for secure HTTPS connections)
- `-mtls`: Enable mutual TLS (optional)
- `-http3`: Enable HTTP/3 support (optional)

### Running in Server Mode

To run the application as a **server** with TLS enabled and HTTP/3 support, use the following command:

```bash
./myapp -mode server -tls-cert /path/to/your/cert.crt -tls-key /path/to/your/key.key -mtls -http3
```

This command will:
- Start the server in **server mode**.
- Use the provided **TLS certificate** and **private key** for secure HTTPS connections.
- Enable **mutual TLS** (mTLS) authentication, which requires both server and client certificates.
- Enable **HTTP/3** support (using QUIC).

### Running in Standalone Mode

If you need to run the application in **standalone mode**, which could be useful for other tasks like background processing or standalone functionalities:

```bash
./myapp -mode standalone
```

This will run the application without starting the server, allowing you to execute other logic in the `standalone` mode.

### Running in RPC Mode

For **RPC mode**, where the application might act as a remote procedure call server:

```bash
./myapp -mode rpc
```

This mode should be used if your application is designed to handle RPC-style requests.

## Configuration Options

You can modify the behavior of the server by passing additional flags for configuration. The most common configuration options include:

- **`-tls-cert`**: Path to the TLS certificate file (e.g., `server.crt`).
- **`-tls-key`**: Path to the TLS private key file (e.g., `server.key`).
- **`-mtls`**: Enable **mutual TLS** (mTLS) to require client certificates.
- **`-http3`**: Enable **HTTP/3** (QUIC) support.

## Accessing the Server

Once the server is running in **server mode**, you can access the server through HTTPS at `https://localhost` or `https://<your-server-ip>`. Ensure that the server is accessible and that the correct ports are open.

For **HTTP/3**, you may need a client (like Chrome or Firefox) that supports QUIC and HTTP/3.

### Example:

- **Access the server on HTTP/3**:
  - Open Chrome or Firefox.
  - Navigate to `https://localhost` (or your server’s IP address).
  - Ensure you are using a QUIC-enabled browser to take advantage of HTTP/3.

## Graceful Shutdown

The server is designed to handle graceful shutdowns. When a termination signal (`SIGINT`, `SIGTERM`) is received, the server will stop accepting new connections and will close existing connections after a 10-second timeout.

## Error Handling

In case of errors, the application will log them and terminate if necessary. Ensure that the following are correctly set up:
- TLS certificate and private key paths.
- QUIC configuration for HTTP/3.
- Correct server modes and flags.

## Example Usage

### Run in Server Mode with mTLS and HTTP/3:

```bash
./myapp -mode server -tls-cert server.crt -tls-key server.key -mtls -http3
```

### Run in Standalone Mode:

```bash
./myapp -mode standalone
```

### Run in RPC Mode:

```bash
./myapp -mode rpc
```


## Code Explanation

### `GenerateQuantumUUID` Function

The **GenerateQuantumUUID** function generates a quantum-resistant UUID in several detailed steps:

1. **QRNG Entropy Generation**: Quantum Random Number Generator (QRNG) is used to gather entropy. This ensures that the UUID is generated using truly random values, rather than pseudo-random numbers, providing stronger security against quantum attacks.
   
2. **System Entropy & Timestamp**: Additional entropy from the system and a timestamp is added to enhance the randomness and context of the UUID.

3. **Multiple Rounds of Hashing**: 
   - **SHAKE256** is used to hash the entropy.
   - **BLAKE3** provides further cryptographic hashing.
   - **SHA3-512** strengthens the final hash output.

4. **Key Derivation**: Uses the **Argon2di** key derivation function with time-dependent salt to generate a cryptographic key for further operations.

5. **Hybrid Cryptography**: 
   - **ECDSA** (Elliptic Curve Digital Signature Algorithm) signs the derived key.
   - **SPHINCS+** (Post-Quantum Signature Scheme) adds another layer of signing for added quantum resistance.

6. **AES Encryption**: The final UUID is masked using AES encryption with the derived key to ensure privacy.

7. **UUID v8 Format**: The final quantum UUID is formatted according to UUIDv8 (custom UUID) specifications for compatibility.

## Use Cases

### 1. **Blockchain Transactions**
   - **Scenario**: When a quantum-resistant UUID is used to uniquely identify a transaction in a blockchain, the metadata helps ensure that the transaction is verified against quantum-safe standards.
   - **Example**: A blockchain system could use **QuantumUUID** as a transaction ID to securely link data entries to specific transactions, ensuring both cryptographic strength and traceability.

### 2. **IoT Device Authentication**
   - **Scenario**: Each IoT device is assigned a **QuantumUUID** to authenticate itself against a server. The metadata provides information about the cryptographic algorithms and expiration, ensuring that devices use valid UUIDs and remain secure.
   - **Example**: A smart thermostat uses a **QuantumUUID** to authenticate with a cloud service, ensuring that the device’s identity is cryptographically verified and resistant to quantum attacks.

### 3. **Secure API Access**
   - **Scenario**: APIs use **QuantumUUID** tokens as part of the authentication process. The metadata ensures proper access control, tracking which users or services can access certain resources and for how long.
   - **Example**: An API service uses **QuantumUUIDs** as access tokens. The metadata indicates the expiration date and access level, ensuring that outdated or unauthorized requests are blocked.

### 4. **Digital Certificates**
   - **Scenario**: **QuantumUUID** can be used as part of a hybrid certificate system to provide secure and quantum-safe certificate generation and verification.
   - **Example**: A user’s digital certificate is signed using **QuantumUUID** to bind their identity to a cryptographically secure and quantum-resistant certificate, which can be verified by others.

## Installation & Usage

### Prerequisites

- Go 1.23 or higher
- External dependencies:
  - `github.com/ashutoshgngwr/go-qrng`
  - `github.com/fdaines/go-sphincs-plus`
  - `golang.org/x/crypto`

### Install Dependencies

```bash
go get github.com/ashutoshgngwr/go-qrng
go get github.com/fdaines/go-sphincs-plus
go get golang.org/x/crypto
```

# Evaluation of GenerateQuantumUUID

To evaluate the collision resistance, global and local uniqueness, and unguessability of the `GenerateQuantumUUID` implementation, we can break it down into specific statistical metrics and assumptions based on cryptographic properties and the entropy of the system.

## 1. Collision Resistance

**Definition**: The probability of two UUIDs being identical when generated independently.

### Entropy Source
- **QRNG entropy**: 64 bytes (512 bits) of randomness.
- **System entropy**: 64 bytes (512 bits) of randomness.
- **Timestamp entropy**: At least 44 bits (assuming nanosecond precision and uniqueness for ~1 day).
- **Total raw entropy**:  
  \[
  512 + 512 + 44 = 1068 \, \text{bits}
  \]

### Hashing Operations
- `SHAKE256`, `BLAKE3`, and `SHA3-512` ensure uniform distribution and cryptographic strength.
- Collision probability for a secure hash function (e.g., SHA3-512) follows the birthday paradox:
  \[
  P_{\text{collision}} \approx 1 - e^{-\frac{n^2}{2 \cdot 2^b}}
  \]
  where \(n\) is the number of UUIDs generated, and \(b\) is the hash output size in bits.

- For \(b = 512\):  
  Generating \(10^{12}\) UUIDs:  
  \[
  P_{\text{collision}} \approx 1 - e^{-\frac{(10^{12})^2}{2 \cdot 2^{512}}} \approx 2.71 \times 10^{-77}
  \]

### Practical Collision Resistance
- **Virtually impossible** for any real-world scenario.

## 2. Global and Local Uniqueness

### Global Uniqueness
UUIDs generated across different systems should not collide.

#### Factors Ensuring Global Uniqueness
- Use of QRNG, which generates truly random bits based on quantum phenomena.
- Inclusion of system entropy, providing additional randomness unique to each system.
- Timestamp ensures UUIDs generated at different moments are unique.

### Local Uniqueness
UUIDs generated within a single system in close temporal proximity should not collide.

#### Factors Ensuring Local Uniqueness
- High-precision timestamp (\(10^9\) nanoseconds per second).
- Independent entropy sources (QRNG + system entropy).

### Statistical Guarantees
- **Number of unique UUIDs for \(n = 10^{12}\) generations**:
  \[
  2^{1068} \, \text{possible UUIDs} \gg 10^{12}.
  \]
- **Global and Local Collision Probability**: Same as above (effectively zero).

## 3. Unguessability

**Definition**: The probability of an adversary guessing a valid UUID.

### Entropy Distribution
- **Total entropy (raw)**: 1068 bits.
- **Post-hashing entropy (SHA3-512)**: 512 bits (output size).
- **Post-encryption entropy (AES-256)**: 256 bits.

### Unguessability Metric
- **Probability of guessing a UUID**:  
  \[
  P_{\text{guess}} = \frac{1}{2^{256}} \approx 8.63 \times 10^{-78}.
  \]
- **Even with \(10^{12}\) attempts per second for \(10^{12}\) years**:  
  \[
  \text{Attempts} = 10^{12} \cdot 10^{12} \cdot 365 \cdot 24 \cdot 60 \cdot 60 \approx 3.15 \times 10^{31}.
  \]
- **Probability of a successful guess**:  
  \[
  P_{\text{guess success}} = \frac{3.15 \times 10^{31}}{2^{256}} \approx 2.7 \times 10^{-46}.
  \]

### Practical Unguessability
- **Quantum-safe** against brute-force guessing.

## Statistical Summary
```markdown
| **Property**              | **Value/Guarantee**                                                                 |
|---------------------------|-------------------------------------------------------------------------------------|
| **Collision Resistance**  | \(P_{\text{collision}} \approx 2.71 \times 10^{-77}\) for \(10^{12}\) UUIDs.       |
| **Global Uniqueness**      | Probability of global collision: effectively zero.                                 |
| **Local Uniqueness**       | Probability of local collision: effectively zero.                                  |
| **Unguessability**         | \(P_{\text{guess}} \approx 8.63 \times 10^{-78}\).                                 |
| **Standards Compliance**   | AES-256, SHA3-512, SPHINCS+, RFC 4122, RFC 9562, SHAKE256 ensure cryptographic robustness. |
```

## Conclusion

This repository provides a secure, quantum-resistant UUID generation system, complete with hybrid cryptography, multiple hashing rounds, and essential metadata. It is designed for modern cryptographic applications requiring strong security, including blockchain, IoT, and API authentication.

