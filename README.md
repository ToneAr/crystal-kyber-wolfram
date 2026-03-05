
# CRYSTALS-Kyber for Wolfram Language

A Wolfram Language paclet providing an interface to the CRYSTALS-Kyber post-quantum Key Encapsulation Mechanism (KEM), selected for standardization by the NIST Post-Quantum Cryptography project.

This paclet wraps the [official Kyber reference implementation](https://github.com/pq-crystals/kyber) via LibraryLink, exposing key generation, encapsulation, and decapsulation as native Wolfram Language functions.

## Requirements

- Wolfram Language 14.0+
- A C compiler (GCC on Linux, Clang on macOS, MSVC on Windows)

## Installation

Install directly from the Wolfram Language:

```wl
PacletInstall["ToneAr/Kyber"]
```

## Usage

```wl
Needs["ToneAr`Kyber`"]
```

### Key Generation

Generate a key pair at a given security level (512, 768, or 1024):

```wl
In[0]  := KyberKeyGen[768]
Out[0] := <| "PublicKey" -> PublicKey[(* ... *)], "PrivateKey" -> PrivateKey[(* ... *)] |>
```

### Encapsulation

Produce a shared secret and ciphertext from a public key:

```wl
In[0]  := KyberEncapsulate[publicKey, 768]
Out[0] := <| "CipherText" -> EncryptedData[(* ... *)], "SharedSecret" -> SymmetricKey[(* ... *)] |>
```

### Decapsulation

Recover the shared secret using the private key:

```wl
In[0]  := KyberDecapsulate[cipherText, privateKey]
Out[0] := SymmetricKey[(* ... *)]
```

### Built-in Cryptography Integration

The paclet also extends `GenerateAsymmetricKeyPair` to support ML-KEM:

```wl
{pub, priv} = GenerateAsymmetricKeyPair["ML-KEM", "ParameterSet" -> 768]
```

## Security Levels

| Parameter Set | NIST Level | Public Key | Secret Key | Ciphertext |
|---------------|------------|------------|------------|------------|
| Kyber512      | 1          | 800 B      | 1632 B     | 768 B      |
| Kyber768      | 3          | 1184 B     | 2400 B     | 1088 B     |
| Kyber1024     | 5          | 1568 B     | 3168 B     | 1568 B     |

## Building the Library

The shared library is built automatically on first use. To build manually:

```bash
make
```

This compiles the Kyber reference implementation for all three parameter sets and links them into a single shared library under `LibraryResources/`.

## Project Structure

```
Kernel/              Wolfram Language source
  Public.wl          Public API and constants
  Private.wl         Library compilation and loading
  Source/Main.wl     Core KEM functions
  Source/Objects.wl   Display formatting for key objects
  Source/BuiltIn.wl   Integration with built-in crypto framework
src/kyber_link.c     LibraryLink C bridge
kyber/               Official Kyber reference implementation (submodule)
```

## License

The Kyber reference implementation is in the public domain. See [kyber/LICENSE](kyber/LICENSE) for details.
