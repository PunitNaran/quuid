# QuantumUUID Generation & Use Cases

## Overview

This project implements a quantum-resistant **UUID** generation function called **QuantumUUID**, leveraging hybrid cryptography and multiple rounds of hashing to ensure robustness against quantum computing threats. The generated **QuantumUUID** is designed to be highly secure, incorporating cryptographic algorithms like ECDSA, SPHINCS+, SHA3-512, and AES encryption.

In addition to the UUID itself, **QuantumUUIDMetadata** is generated to provide crucial information about the UUID's creation and cryptographic strength. This metadata can be used for auditability, compliance, and proper key management.

## Key Features

- **Quantum-Resistant**: Utilizes cryptographic algorithms that are resistant to quantum computing threats.
- **Hybrid Cryptography**: Combines ECDSA (Elliptic Curve Digital Signature Algorithm) and SPHINCS+ (a post-quantum signature scheme) for maximum security.
- **Multiple Hashing Rounds**: Uses SHA3-512, BLAKE3, and SHAKE256 to process the entropy and enhance security.
- **Metadata**: Associates essential metadata with each generated UUID for better traceability, security assurance, and version control.

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

### Metadata Structure

Each generated UUID is accompanied by a **QuantumUUIDMetadata** object, which includes the following information:

- **created_at**: Timestamp of when the UUID was created.
- **uuid_version**: Version of the UUID (e.g., `v8`).
- **signature_algorithm**: Specifies the algorithms used for signing (ECDSA, SPHINCS+).
- **key_derivation**: Information about the key derivation function and salt used.
- **quantum_resistance_strength**: The level of quantum resistance.
- **use_case**: The intended use for the UUID (e.g., blockchain transactions, IoT authentication).
- **valid_until**: Expiration or validity period of the UUID.
- **issuer**: The entity responsible for generating the UUID.
- **access_level**: Defines access permissions associated with the UUID.
- **uuid_type**: Identifies the type of UUID (quantum-resistant UUID).

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

---

## Mermaid Diagrams: Real-World Scenarios

Below are Mermaid diagrams explaining how **QuantumUUID** and its associated **metadata** can be used in various real-world scenarios.

### **1. Blockchain Transaction ID Usage**

```mermaid
graph TD;
    A[User submits transaction] --> B[Generate QuantumUUID for transaction];
    B --> C[Include UUID in transaction data];
    C --> D[QuantumUUID Metadata: Contains timestamp, signature algorithm, and access level];
    D --> E[Store transaction in blockchain];
    E --> F[Verify transaction using QuantumUUID and metadata];
    F --> G[Ensure cryptographic strength (ECDSA, SPHINCS+) for verification];
    G --> H[Complete blockchain transaction securely];
```

### **2. IoT Device Authentication Flow**

```mermaid
graph TD;
    A[IoT Device requests authentication] --> B[Generate QuantumUUID for device];
    B --> C[Attach QuantumUUID Metadata (created_at, signature_algorithm)];
    C --> D[Send UUID and metadata to authentication server];
    D --> E[Server verifies QuantumUUID and metadata (ECDSA, SPHINCS+)];
    E --> F[Authenticate device and grant access];
    F --> G[Track access using metadata (access_level)];
    G --> H[Expire UUID after defined period (valid_until)];
```

### **3. API Access with QuantumUUID Authentication**

```mermaid
graph TD;
    A[Client makes API request] --> B[Generate QuantumUUID for authentication];
    B --> C[Attach QuantumUUID Metadata (use_case, valid_until)];
    C --> D[Send QuantumUUID and metadata to API server];
    D --> E[API verifies QuantumUUID with metadata (signature algorithm, access level)];
    E --> F[Provide access or deny based on metadata checks];
    F --> G[Track access usage based on metadata];
    G --> H[Expire or renew QuantumUUID based on validity period];
```

### **4. Digital Certificate with QuantumUUID**

```mermaid
graph TD;
    A[User requests certificate] --> B[Generate QuantumUUID for certificate];
    B --> C[Attach QuantumUUID Metadata (uuid_version, issuer, expiration_date)];
    C --> D[Sign certificate using QuantumUUID];
    D --> E[Distribute signed certificate to user];
    E --> F[Certificate verification using QuantumUUID and metadata];
    F --> G[Ensure cryptographic strength with SPHINCS+ and ECDSA];
    G --> H[Validate user's identity securely with quantum-resistant certificate];
```

---

## Installation & Usage

### Prerequisites

- Go 1.18 or higher
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

### Example Metadata Output

```json
{
    "uuid": "2f98a0b9-91f1-43d3-a99a-98d7b8e7614a",
    "metadata": {
        "created_at": "2025-01-14T12:00:00Z",
        "uuid_version": "v8",
        "signature_algorithm": "ECDSA, SPHINCS+",
        "key_derivation": "Argon2di with SHA3-512, salt: <random_salt>",
        "quantum_resistance_strength": "high",
        "use_case": "blockchain_transaction",
        "valid_until": "2025-01-15T12:00:00Z",
        "issuer": "QuantumUUIDGenerator",
        "access_level": "read-write",
        "uuid_type": "Quantum-resistant UUID"
    }
}
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

