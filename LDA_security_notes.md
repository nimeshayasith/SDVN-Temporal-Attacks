# LDA_security.py - Beginner Notes

**Main file:** `LDA_security.py`  
**Related example:** `team_notes.md`  
**Purpose of this document:** Explain `LDA_security.py` from the beginning for someone who does not already know the file, the design, or the security concepts inside it.

---

## Table of Contents

1. [What This File Is](#1-what-this-file-is)
2. [Short Summary of the Whole File](#2-short-summary-of-the-whole-file)
3. [Big Security Goal of the File](#3-big-security-goal-of-the-file)
4. [High-Level Structure of the File](#4-high-level-structure-of-the-file)
5. [Step-by-Step Runtime Flow](#5-step-by-step-runtime-flow)
6. [Security Methods Used in This File](#6-security-methods-used-in-this-file)
7. [Why Each Security Method Is Used](#7-why-each-security-method-is-used)
8. [CSV Storage Design](#8-csv-storage-design)
9. [Controller Class Explained](#9-controller-class-explained)
10. [Node Class Explained](#10-node-class-explained)
11. [Important Inputs and Flags](#11-important-inputs-and-flags)
12. [Important Observations About the Design](#12-important-observations-about-the-design)
13. [Simple Mental Model](#13-simple-mental-model)
14. [What You Should Remember Most](#14-what-you-should-remember-most)

---

## 1. What This File Is

`LDA_security.py` is a Python security utility script for your SDVN-related project.

Its job is to perform security operations for:

- a controller
- network nodes
- message protection between communicating parties

It supports:

- RSA key generation
- RSA digital signatures
- RSA encryption/decryption
- HMAC creation and verification
- AES key generation and AES encryption/decryption
- ECC key generation
- ECDH shared-key establishment
- key expiry checking
- CSV-based storage of keys and outputs

This file is not a simple one-purpose script.  
It is a **multi-operation security toolbox** controlled by command-line flags.

---

## 2. Short Summary of the Whole File

If we summarize the file in one paragraph:

`LDA_security.py` is a classical cryptography management script that lets the controller and nodes perform different security tasks on demand. The main active security methods are **RSA** for digital signatures and public-key encryption, **HMAC-SHA256** for message authentication, **AES-256** for symmetric encryption, and **ECC/ECDH** for shared-key generation. The script reads command-line flags, performs the requested operation, and stores or retrieves keys, signatures, hashes, ciphertext, and verification results through CSV files.

---

## 3. Big Security Goal of the File

This file tries to solve the main security needs of a communicating system:

1. **Authentication**
   Verify who sent a message.

2. **Integrity**
   Detect whether a message was changed.

3. **Confidentiality**
   Keep message contents secret from others.

4. **Key management**
   Generate, share, store, and reuse keys.

5. **Session security**
   Support per-session keys and expiry times.

So this file is not just about encrypting text.  
It is trying to manage a full small security workflow.

---

## 4. High-Level Structure of the File

The file can be understood in five major parts.

### Part A - Imports

The file imports classical cryptography libraries from `Crypto`, including:

- `RSA`
- `AES`
- `PKCS1_OAEP`
- `pkcs1_15`
- `SHA256`
- `ECC`
- `HKDF`
- `pad`, `unpad`

It also imports:

- `hmac`
- `hashlib`
- `csv`
- `base64`
- `shlex`

There are also imports like `sympy` and `py_ecc.optimized_bn128`, which relate to the zk-SNARK experiment block near the end.

### Part B - `parse_arguments()`

This function reads the command-line input and decides what the script should do.

Examples of actions it can enable:

- generate RSA keys
- sign a message
- verify a signature
- generate HMAC keys
- create HMAC values
- verify HMAC values
- generate ECC keys
- derive ECDH shared keys
- encrypt/decrypt using AES

### Part C - CSV helper functions

This file uses many helper functions to read and write CSV data.

Examples:

- `search_csv_nodeid`
- `search_csv_nodeid_and_key`
- `search_other_other_csv_item`
- `add_csv_element`
- `add_other_other_csv_element`
- `update_csv_element`

These functions are essential because almost all security state is stored in CSV files.

### Part D - `SecurityManager_controller`

This is the main controller-side security class.  
It contains the most complete active security workflow.

### Part E - `SecurityManager_node`

This class contains node-side logic such as:

- RSA key generation
- HMAC creation
- AES operations
- signature verification

### Part F - Bottom execution block

The script ends with:

- `if is_controller:`
- `if is_node:`

and then runs only the operations requested by the parsed flags.

---

## 5. Step-by-Step Runtime Flow

This section explains what happens when the file runs.

### Step 1 - Script starts

The file starts timing its execution:

```python
start = time.time()
```

### Step 2 - Command-line arguments are parsed

`parse_arguments()` reads text input like:

- `is_controller=true`
- `node_id=1`
- `message=hello`
- `generate_dig_rsa_key_pair=true`
- `sign_data=true`

and converts them into Python variables.

This means the file is **command-driven**.

### Step 3 - The message and context variables are prepared

The script stores values like:

- node ID
- other node ID
- port ID
- message
- signature
- hash value
- message type

These values are then used by the requested security method.

### Step 4 - CSV paths are defined

The file defines fixed CSV files such as:

- `security_data.csv`
- `security_AES_data.csv`
- `security_HMAC2_data.csv`
- `security_global_HMAC_data.csv`
- `security_node1_HMAC_data.csv`
- `security_node2_HMAC_data.csv`
- `security_nodepair_AES_data.csv`
- `security_ECDH_data.csv`

These CSV files act like the persistent storage layer.

### Step 5 - Helper search/update functions become available

The file defines many reusable CSV utilities so later security methods can:

- look up a key
- see whether an entry already exists
- add a new row
- update an old row

### Step 6 - The controller or node branch is chosen

If `is_controller` is true, the controller security flow runs.  
If `is_node` is true, the node security flow runs.

In practice, the controller flow is the richer and more central path.

### Step 7 - Requested security operation is performed

Examples:

- generate RSA digital signature keys
- sign data
- verify signatures
- generate HMAC session keys
- create HMAC values
- verify HMAC values
- generate AES keys
- encrypt/decrypt with AES
- generate ECC keys
- derive ECDH shared keys

### Step 8 - Results are stored back into CSV files

This is a major design feature of the file.  
Most operations do not stop at printing results; they also store the outputs in CSV form.

### Step 9 - Execution time is printed

At the end, the script prints the total runtime in microseconds.

---

## 6. Security Methods Used in This File

This is the most important concept section.

## 6.1 RSA

**Type:** Classical public-key cryptography

Used in the file for:

- digital signature key generation
- signing data
- verifying signatures
- encrypting data
- decrypting data

Main related methods:

- `generate_dig_rsa_key_pair()`
- `sign_data()`
- `verify_signature()`
- `get_rsa_keys()`
- `encrypt_rsa()`
- `decrypt_rsa()`

### What RSA is doing here

RSA plays two roles:

1. **Digital signature role**
   Used with `pkcs1_15` and `SHA256`.

2. **Encryption role**
   Used with `PKCS1_OAEP`.

So RSA is one of the most central methods in this file.

---

## 6.2 HMAC with SHA-256

**Type:** Message authentication code

Used for:

- global HMAC creation
- session HMAC set 1
- session HMAC set 2
- HMAC verification

Main related methods:

- `set_global_hmac_keys()`
- `set_session_hmac_keys_set1()`
- `set_session_hmac_keys_set2()`
- `create_hmac()`
- `verification_hmac()`

### What HMAC is doing here

HMAC provides:

- integrity
- authentication using a shared secret

It is lighter than public-key signatures and useful for repeated communication once both sides share a secret.

---

## 6.3 AES-256

**Type:** Symmetric encryption

Used for:

- controller/node pair protection
- node-to-node pair encryption

Main related methods:

- `generate_own_aes_key()`
- `set_aes_key_for_pair()`
- `encrypt_aes()`
- `decrypt_aes()`

### What AES is doing here

AES is used as the fast symmetric cipher after a key is available.

This is normal in security systems:

- public-key methods manage identity or key sharing
- AES handles the actual message encryption efficiently

---

## 6.4 ECC / ECDH

**Type:** Elliptic curve cryptography and key agreement

Main related methods:

- `generate_ecc_key_pair()`
- `compute_ecc_symmetric_key()`
- `derive_key()`
- `encrypt_ecc()`
- `decrypt_ecc()`

### What ECC/ECDH is doing here

Two sides create a shared secret using elliptic-curve math.  
Then `HKDF` derives a fixed-length symmetric key from that shared secret.

This derived key is later used for symmetric encryption.

---

## 6.5 HKDF

**Type:** Key derivation function

Used in:

- `derive_key()`

### What HKDF is doing here

The raw shared secret from ECDH is not used directly.  
Instead, the file derives a proper symmetric key from it using `HKDF` with `SHA256`.

This is good practice because:

- the shared secret may not be in the best direct form for AES usage
- key derivation gives a clean, fixed-length result

---

## 6.6 SHA-256

**Type:** Cryptographic hash function

Used in:

- RSA signing
- RSA verification
- HMAC creation
- HKDF internals

### What SHA-256 is doing here

SHA-256 is used to:

- hash message data before signing
- support HMAC authentication
- support key derivation

It is a foundational building block in the file.

---

## 6.7 zk-SNARK experimental block

Near the end, there is a triple-quoted experimental example involving `ZKSNARKHMAC`.

This shows ideas like:

- HMAC constraint creation
- QAP generation
- proof generation
- proof verification

### Important note

This block is not part of the normal active execution path.  
It behaves more like a preserved experiment or concept demonstration.

---

## 7. Why Each Security Method Is Used

This section answers the "why do we use this method?" question directly.

### RSA: Why use it?

RSA is used because it gives two important things:

- digital signatures
- public-key encryption

Why that matters:

- a controller can sign messages so nodes can verify them
- a node’s public key can be used to encrypt data meant only for that node

So RSA solves both identity and confidentiality roles in one design.

### HMAC: Why use it?

HMAC is used when two sides already share a secret key and want a fast way to check:

- is this message authentic?
- was this message changed?

Why it is useful:

- lighter than public-key signatures
- practical for repeated session communication
- supports global-key mode and session-key mode

### AES: Why use it?

AES is used because symmetric encryption is efficient.

Why it is important:

- public-key encryption is usually heavier
- AES is better for protecting actual message content repeatedly

So AES is used once a secret key already exists.

### ECC/ECDH: Why use it?

ECDH is used to let two sides derive the same symmetric key without sending that key directly.

Why that matters:

- safer shared-secret establishment
- supports secure symmetric encryption later

### HKDF: Why use it?

HKDF converts ECDH shared material into a proper 32-byte derived key.

Why that matters:

- stronger key handling
- fixed-size output
- cleaner symmetric-key usage

### SHA-256: Why use it?

SHA-256 is used because many security methods depend on a secure hash.

It helps with:

- signing
- verification
- HMAC
- key derivation

---

## 8. CSV Storage Design

One of the most important practical ideas in this file is this:

**Security data is stored in CSV files, not just in memory.**

### Examples of stored data

- RSA public keys
- RSA private keys
- ECC public/private keys
- HMAC secret keys
- AES pair keys
- signatures
- ciphertext
- decrypted outputs
- HMAC verification results

### Why this design may have been chosen

- easy to inspect by hand
- easy to debug
- easy to share between separate calls of the script
- no database required

### Cost of this design

- many helper functions are needed
- column positions become very important
- plain CSV is fragile if formats change
- private or secret values are stored in readable/decodable form

### Important practical note

This file often stores keys as:

- plain strings
- hex strings
- base64 strings

That is useful for development and testing, but risky for a production-grade secure system.

---

## 9. Controller Class Explained

The main active class is:

```python
class SecurityManager_controller:
```

### What the controller stores

Important controller attributes include:

- `global_hmac_keys`
- `session_hmac_keys_set1`
- `session_hmac_keys_set2`
- `dig_rsa_public_keys`
- `dig_rsa_private_keys`
- `dig_ecc_alice_private_keys`
- `dig_ecc_bob_private_keys`
- `dig_ecc_alice_public_keys`
- `dig_ecc_bob_public_keys`
- `rsa_public_keys`
- `aes_keys`
- key expiry dictionaries

This shows that the controller is the central security manager.

### Main controller responsibilities

`generate_dig_rsa_key_pair(node_id)`

- generates RSA signature key pair
- stores it in CSV

`sign_data(data, node_id, port_id, other_node_id, save=False)`

- signs data using RSA private key
- hashes with SHA-256
- signs using `pkcs1_15`
- stores signature if requested

`verify_signature(...)`

- verifies RSA signature using stored public key

`set_global_hmac_keys(node_id)`

- generates a global HMAC secret key

`set_session_hmac_keys_set1(node_id)`

- creates first kind of session HMAC key

`set_session_hmac_keys_set2(node_id, other_node_id, port_id)`

- creates second kind of session HMAC key for node pair plus port context

`create_hmac(...)`

- chooses the right HMAC key
- builds an HMAC over the message using SHA-256
- optionally stores the result

`verification_hmac(...)`

- compares received and generated HMAC values
- stores verification result

`generate_own_aes_key()`

- creates controller AES key

`set_aes_key_for_pair(...)`

- creates AES key shared between a node pair
- stores that key for both communication directions

`encrypt_aes(...)`

- reads AES pair key
- pads plaintext
- encrypts using AES
- stores ciphertext

`decrypt_aes(...)`

- reads key and ciphertext
- decrypts and unpads
- stores decrypted value

`generate_ecc_key_pair(node_id)`

- creates ECC key pairs
- exports and stores them in CSV

`compute_ecc_symmetric_key(...)`

- computes ECDH shared secret

`derive_key(...)`

- derives symmetric key from ECDH output via HKDF

`encrypt_ecc(...)` and `decrypt_ecc(...)`

- use the ECDH-derived symmetric key for message protection

### Key expiry logic

The controller also tracks expiry times for:

- digital signature keys
- HMAC set 1 keys
- HMAC set 2 keys

This is important because the script is not only creating keys; it is also trying to manage key lifetime.

---

## 10. Node Class Explained

The file also contains:

```python
class SecurityManager_node:
```

This class is smaller than the controller class.

### What it supports

- RSA key pair generation
- HMAC key storage and creation
- RSA signature verification
- AES pair encryption/decryption
- RSA decryption

### Why this class exists

The controller is the central manager, but individual nodes still need their own local abilities.

For example, a node may need to:

- hold its own RSA key pair
- receive an AES pair key
- verify controller signatures
- create HMAC outputs
- decrypt RSA-encrypted content intended for it

### Practical observation

The node class depends on data coming from the controller and is less complete than the controller class.  
So when learning this file, it is better to understand the controller flow first.

---

## 11. Important Inputs and Flags

This file depends heavily on command-line flags.

Important ones include:

- `is_controller`
- `is_node`
- `create_security_manager_con`
- `netsize`
- `node_id`
- `other_node_id`
- `port_id`
- `pid`
- `message`
- `signature`
- `hashval`
- `msg_type`
- `generate_dig_rsa_key_pair`
- `generate_dig_ecc_key_pair`
- `generate_own_aes_key`
- `encrypt_ECDH`
- `decrypt_ECDH`
- `sign_data`
- `verify_signature`
- `verify_HMAC`
- `initiate_session1`
- `initiate_session2`
- `create_hmac_global`
- `create_hmac_set1`
- `create_hmac_set2`
- `verify_key_expiry`
- `encrypt_aes_node_pair`
- `decrypt_aes_node_pair`

### Why these flags matter

This script does not follow one single built-in sequence.  
Instead, you activate exactly the operations you want.

That means understanding the file requires understanding:

- what each flag means
- what prerequisites it has
- what CSV entries it expects to already exist

---

## 12. Important Observations About the Design

These are some important things you should notice while studying the file.

### Observation 1 - This is a workflow script, not just a crypto library

This file does not only perform cryptography.  
It also manages:

- storage
- reuse of old values
- pairing relationships
- port-aware entries
- session handling
- expiry logic

### Observation 2 - CSV is the coordination backbone

Many steps depend on values created earlier and stored in CSV.

So the script works like a chain:

1. generate something
2. store it
3. later read it back
4. use it for the next security step

### Observation 3 - This file uses many classical methods together

The core active methods are:

- RSA
- HMAC
- AES
- ECC/ECDH

This means the file is building a layered classical security model.

### Observation 4 - AES mode choice

The file uses `AES.MODE_ECB` in multiple places.

ECB works at a technical level, but in modern secure design it is usually considered weak for structured data because it can leak patterns.  
So this is something to remember as a design limitation.

### Observation 5 - Sensitive data is stored in decodable forms

Keys and outputs are often stored as:

- raw strings
- hex
- base64

That is convenient for experiments, but not ideal for production security.

### Observation 6 - The file includes experimental zk-SNARK ideas

The zk-SNARK block near the end suggests the project explored more advanced proof-based integrity ideas, even though that block is not part of the main active runtime.

---

## 13. Simple Mental Model

The easiest way to remember this file is to see it as four layers.

### Layer 1 - Argument parser

"What action was requested?"

### Layer 2 - CSV storage layer

"Where do we fetch or store keys and outputs?"

### Layer 3 - Security engine

"Use RSA, HMAC, AES, or ECDH/ECC to perform the requested operation."

### Layer 4 - Role-based execution

"If this script is acting for the controller, run controller logic. If it is acting for a node, run node logic."

---

## 14. What You Should Remember Most

If you only remember a few things about `LDA_security.py`, remember these:

1. It is a command-driven classical security management script.
2. Its main active methods are **RSA**, **HMAC-SHA256**, **AES-256**, and **ECC/ECDH**.
3. RSA is used for signatures and public-key encryption.
4. HMAC is used for shared-secret message authentication.
5. AES is used for symmetric encryption after a key is available.
6. ECC/ECDH is used to derive shared symmetric keys.
7. CSV files are central to storing keys, hashes, signatures, ciphertext, and verification results.
8. The controller class is the main active security coordinator in the file.
9. The node class supports local verification and symmetric operations.
10. The file is practical and experiment-oriented, not a polished production security module.

---

## Final Understanding in One Paragraph

`LDA_security.py` is a controller-and-node security utility that combines several classical cryptographic methods into one workflow-driven script. It uses command-line flags to choose actions, CSV files to store and retrieve security state, RSA for identity and public-key protection, HMAC for fast shared-secret authentication, AES for symmetric encryption, and ECC/ECDH plus HKDF for shared-key establishment. The best way to understand the file is to view it as a central security orchestrator for experiments, where the controller manages most of the security lifecycle and the nodes consume or verify the resulting keys and protected messages.

