# LDA_PQ_security.py - Beginner Notes

**Main file:** `LDA_PQ_security.py`  
**Related example:** `team_notes.md`  
**Purpose of this document:** Explain `LDA_PQ_security.py` from the beginning, in simple language, so a reader who does not know the file can still understand what it does, how it runs, and which security methods it uses.

---

## Table of Contents

1. [What This File Is](#1-what-this-file-is)
2. [Short Summary of the Whole File](#2-short-summary-of-the-whole-file)
3. [Big Idea: What Problem the File Solves](#3-big-idea-what-problem-the-file-solves)
4. [High-Level Structure of the File](#4-high-level-structure-of-the-file)
5. [Step-by-Step Runtime Flow](#5-step-by-step-runtime-flow)
6. [Important Security Methods Used in This File](#6-important-security-methods-used-in-this-file)
7. [Why Each Security Method Is Used](#7-why-each-security-method-is-used)
8. [CSV Files and Stored Data](#8-csv-files-and-stored-data)
9. [Controller Class Explained](#9-controller-class-explained)
10. [Node Class Explained](#10-node-class-explained)
11. [Important Flags / Inputs](#11-important-flags--inputs)
12. [Important Design Observations](#12-important-design-observations)
13. [Simple Mental Model](#13-simple-mental-model)
14. [What You Should Remember Most](#14-what-you-should-remember-most)

---

## 1. What This File Is

`LDA_PQ_security.py` is a Python security utility file for your SDVN-related project.  
Its job is to perform security operations for nodes and the controller, such as:

- generating keys
- encrypting messages
- decrypting messages
- signing messages
- verifying signatures
- creating HMAC values
- storing security data inside CSV files

This file is called using command-line arguments, and those arguments decide which security operation should run.

---

## 2. Short Summary of the Whole File

If we summarize the file in one paragraph:

`LDA_PQ_security.py` is a command-driven security manager that supports both classical and post-quantum style operations. In practice, the active part of this file mainly uses **Falcon-1024** for post-quantum digital signatures and **ASCON-128** for lightweight authenticated encryption. It also contains older or secondary code for **RSA**, **AES**, **ECC/ECDH**, and **HMAC**, but a large part of that classical section is currently wrapped inside triple-quoted blocks, so it behaves more like preserved or experimental code than the main active flow.

---

## 3. Big Idea: What Problem the File Solves

In a networked system, we usually need four protections:

1. **Confidentiality**
   Only the intended receiver should read the message.

2. **Integrity**
   The message should not be changed secretly.

3. **Authentication**
   The receiver should know who sent the message.

4. **Non-repudiation / proof of origin**
   A sender should not be able to deny a message they signed.

This file tries to provide those protections by combining different security mechanisms.

---

## 4. High-Level Structure of the File

The file can be understood in five main parts.

### Part A - Imports and experiments at the top

At the top, the file imports:

- standard Python modules like `os`, `sys`, `csv`, `time`, `shlex`
- `oqs` for post-quantum cryptography
- `ascon` for lightweight authenticated encryption

There are also some commented example blocks showing:

- how ASCON encryption works
- how Kyber KEM works
- how Falcon signatures work

These top blocks are more like test/demo material.

### Part B - `parse_arguments()`

This is the entry gate of the file. It reads command-line flags such as:

- `is_controller=true`
- `generate_FALCON=true`
- `encrypt_ASCON=true`
- `verify_FALCON=true`

So this file does not behave like a single fixed program.  
It behaves like a toolbox, and the flags choose the tool.

### Part C - CSV helper functions

There are many helper functions such as:

- `search_csv_nodeid`
- `search_csv_nodeid_and_key`
- `search_other_other_csv_nodeid`
- `add_csv_element`
- `update_csv_element`

These functions are very important because this file stores almost everything in CSV files:

- public keys
- private keys
- nonces
- ciphertext
- signatures
- verification results

### Part D - `SecurityManager_controller`

This class handles the controller-side security logic.  
This is the main active class in the file.

Its active post-quantum methods include:

- Falcon key generation
- Falcon signing
- Falcon verification
- ASCON key/nonce generation
- ASCON encryption
- ASCON decryption

Inside a large triple-quoted block, it also includes older classical functions for:

- RSA signatures
- AES encryption
- ECC/ECDH
- HMAC
- key expiry

### Part E - Bottom execution block

Near the end, the script checks:

- `if is_controller:`
- `if is_node:`

Then it runs the requested operations based on the parsed flags.

---

## 5. Step-by-Step Runtime Flow

This is the easiest way to understand how the file behaves at runtime.

### Step 1 - The script starts

The file starts running immediately when Python executes it.

It records start time:

```python
start = time.time()
```

This is for execution-time measurement.

### Step 2 - Arguments are parsed

`parse_arguments()` reads the command line and turns text flags into Python variables.

Examples:

- `generate_FALCON=true` means generate Falcon key pair
- `sign_FALCON=true` means sign a message using Falcon
- `encrypt_ASCON=true` means encrypt using ASCON
- `msg_type=1` or `msg_type=2` helps choose which CSV layout/path to use

This step is important because the file is **flag-driven**.

### Step 3 - Global CSV paths are defined

The file defines many fixed CSV locations such as:

- `security_data.csv`
- `security_node1_dig_sig_data.csv`
- `security_node2_dig_sig_data.csv`
- `security_ASCON_data1.csv`
- `security_ASCON_data2.csv`
- `security_ASCON_data3.csv`
- `security_ASCON_data4.csv`

These files act like a simple persistence layer.

### Step 4 - The controller or node path is selected

If `is_controller=True`, the controller block runs.  
If `is_node=True`, the node block runs.

In this file, the controller path is the main active one.

### Step 5 - The selected security action runs

Examples:

- generate Falcon keys
- sign a message
- verify a signature
- generate ASCON key and nonce
- encrypt a message with ASCON
- decrypt a message with ASCON

### Step 6 - Results are stored in CSV files

This file does not only compute results in memory.  
It usually writes them into CSV files for later reuse by other program steps.

### Step 7 - Execution ends

At the bottom, the script measures elapsed time and prints it.

---

## 6. Important Security Methods Used in This File

This section is the most important conceptual part.

## 6.1 Falcon-1024

**Type:** Post-quantum digital signature  
**Library used:** `oqs.Signature`  
**Main methods:**

- `generate_FALCON1024_key_pair()`
- `pq_sign()`
- `pq_sign_node2()`
- `pq_verify()`
- `pq_verify_node2()`

**What it does:**  
Falcon is used to create and verify digital signatures.

**Security goal:**  
Authentication, integrity, and sender proof.

**Where used in the file:**  
This is one of the two main active security systems in the file.

---

## 6.2 ASCON-128

**Type:** Lightweight authenticated encryption  
**Library used:** `from ascon import encrypt, decrypt`  
**Main methods:**

- `generate_ASCON_secret_key()`
- `encrypt_ASCON()`
- `decrypt_ASCON()`

**What it does:**  
ASCON encrypts plaintext and supports authenticated encryption using:

- secret key
- nonce
- associated data

**Security goal:**  
Confidentiality and integrity.

**Where used in the file:**  
This is the other main active security system in the file.

---

## 6.3 Kyber1024 KEM

**Type:** Post-quantum key encapsulation mechanism  
**Functions shown:**

- `pq_encrypt()`
- `pq_decrypt()`

**What it does:**  
Kyber is designed to establish a shared secret securely.

**Important note:**  
In this file, the Kyber code is inside a triple-quoted example block near the top.  
So it is present as a demonstration, but it is not part of the main active runtime flow.

---

## 6.4 RSA

**Type:** Classical public-key cryptography  
**Used for:** encryption and signatures in the older design

Examples in the file include:

- `generate_dig_rsa_key_pair()`
- `sign_data()`
- `verify_signature()`
- `encrypt_rsa()`
- `decrypt_rsa()`

**Important note:**  
Most of this controller-side RSA logic appears inside a large triple-quoted block, meaning it is not part of the currently active main code path.

---

## 6.5 AES-256

**Type:** Symmetric encryption  
**Used for:** controller data encryption and node-pair encryption

Examples in the file include:

- `generate_own_aes_key()`
- `set_aes_key_for_pair()`
- `encrypt_aes()`
- `decrypt_aes()`

**Important note:**  
This exists in the file, but much of the controller-side AES usage is also in the preserved/commented section.

---

## 6.6 ECC / ECDH

**Type:** Elliptic curve cryptography and key agreement  
**Used for:** deriving a shared symmetric key

Examples:

- `generate_ecc_key_pair()`
- `compute_ecc_symmetric_key()`
- `derive_key()`
- `encrypt_ecc()`
- `decrypt_ecc()`

**What it does:**  
Two parties compute the same shared secret, then derive a symmetric key from it using `HKDF`.

**Important note:**  
This logic exists in the older/classical section, not in the main active post-quantum flow.

---

## 6.7 HMAC

**Type:** Message authentication code  
**Used for:** integrity checking with secret keys

Examples:

- `create_hmac()`
- session HMAC key methods
- expiry-check methods

**What it does:**  
Creates a keyed hash using `hashlib.sha256`.

**Important note:**  
This is part of the older security framework preserved in the file.

---

## 7. Why Each Security Method Is Used

This is the "why" section you asked for.

### Falcon-1024: Why use it?

Falcon is used because digital signatures are needed to prove:

- who sent a message
- that the message was not changed

It is a **post-quantum** signature method, so the design is trying to move beyond only classical security.

Why this is useful in your project:

- controller or node messages can be signed
- the receiver can verify the sender
- stored signature results can be reused later

### ASCON-128: Why use it?

ASCON is used for secure message encryption with low overhead.

Why it fits this file:

- it is lightweight
- it supports authenticated encryption
- it uses a key and nonce
- it also accepts associated data

So it protects both:

- message secrecy
- message authenticity/integrity

### Kyber1024: Why include it?

Kyber is for secure shared-secret establishment in a post-quantum setting.

Even though it is not active in the main runtime path here, it shows the file’s security direction:

- post-quantum key establishment
- post-quantum signatures

That means the file is not only classical; it is moving toward quantum-resistant security.

### RSA: Why is it here?

RSA is a well-known classical public-key method.  
It appears to be part of an older security design in this project.

Reasons it would be used:

- encrypt small messages or keys
- sign messages
- verify identity

But in this file, Falcon seems to be the newer preferred signature path.

### AES: Why is it here?

AES is fast and practical for bulk symmetric encryption.

Public-key methods are usually heavier, so a common pattern is:

- use public-key or key agreement to exchange a secret
- use AES for actual message encryption

That is why AES appears as link-level or controller-level symmetric protection.

### ECC/ECDH: Why is it here?

ECDH allows two sides to create a shared secret without sending that secret directly.

Why this matters:

- safer key establishment
- shared symmetric key can then be used for encryption

### HMAC: Why is it here?

HMAC is used when you want lightweight message integrity and sender authentication based on a shared secret.

Why it is useful:

- faster than public-key signatures
- good for session-based message validation
- useful when both sides already share a key

---

## 8. CSV Files and Stored Data

One of the biggest practical ideas in this file is this:

**The file stores security state in CSV files instead of keeping everything only in memory.**

That means keys and outputs survive beyond one function call.

### Main storage roles

`security_data.csv`

- central storage for node-related key material
- Falcon public/private keys are written here
- ASCON key and nonce are written here

`security_node1_dig_sig_data.csv`

- stores node 1 signature output and verification result

`security_node2_dig_sig_data.csv`

- stores node 2 signature output and verification result

`security_ASCON_data1.csv` to `security_ASCON_data4.csv`

- store encrypted/decrypted ASCON data depending on message type

### Why this design was likely chosen

- easy to inspect manually
- easy to exchange data with other scripts
- simple persistence without a database

### Cost of this design

- many helper functions are needed
- code becomes longer
- CSV format is fragile if columns change
- secret keys are being stored in plain CSV form, which is convenient but risky

---

## 9. Controller Class Explained

The main active class is:

```python
class SecurityManager_controller:
```

### What this class stores

Important active attributes include:

- `self.ascon_key`
- `self.ascon_nonce`
- `self.dig_Falcon1024_public_keys`
- `self.dig_Falcon1024_private_keys`

This means the controller mainly manages:

- ASCON encryption materials
- Falcon signature materials

### Important active methods

`generate_FALCON1024_key_pair(node_id)`

- creates Falcon public/private key pair
- converts both to hex
- stores them in CSV

`pq_sign(...)`

- signs a message using Falcon
- stores signature hex in node1 signature CSV

`pq_sign_node2(...)`

- same idea, but writes to node2 signature CSV

`pq_verify(...)`

- verifies Falcon signature for node1 flow
- stores verification result

`pq_verify_node2(...)`

- verifies Falcon signature for node2 flow

`generate_ASCON_secret_key(node_id)`

- creates a random 16-byte key
- creates a random 16-byte nonce
- stores both in CSV

`encrypt_ASCON(...)`

- reads key and nonce from CSV
- encrypts plaintext with associated data
- writes ciphertext hex to the correct ASCON CSV

`decrypt_ASCON(...)`

- reads key and nonce
- decrypts ciphertext
- stores plaintext result in CSV

### Very important controller observation

The controller class contains a large triple-quoted block with more classical methods.  
That means the class is partly:

- **active PQ/ASCON implementation**
- **part archive of older classical security code**

This is one of the most important things to understand about the file.

---

## 10. Node Class Explained

The file also has:

```python
class SecurityManager_node:
```

This class is smaller and looks more classical.

### What it supports

- RSA key pair generation
- global HMAC key generation
- storing session HMAC keys
- RSA decryption
- AES encryption/decryption for node pairs
- signature verification using a received public key

### Why it exists

This class represents per-node security behavior, while the controller class represents centralized security behavior.

### Important practical note

Although the node class exists, the bottom `is_node` block depends on shared controller state and looks less complete/less central than the controller flow.  
The controller path is clearly the main operational path in this file.

---

## 11. Important Flags / Inputs

The file is highly dependent on command-line flags.

Important ones include:

- `is_controller`
- `is_node`
- `create_security_manager_con`
- `node_id`
- `other_node_id`
- `port_id`
- `message`
- `msg_type`
- `generate_FALCON`
- `sign_FALCON`
- `verify_FALCON`
- `generate_ASCON_key`
- `encrypt_ASCON`
- `decrypt_ASCON`

### What `msg_type` seems to do

`msg_type` chooses which communication/data case is being handled.

In the ASCON section, it selects among:

- `security_ASCON_data1.csv`
- `security_ASCON_data2.csv`
- `security_ASCON_data3.csv`
- `security_ASCON_data4.csv`

In the Falcon section, it also affects whether node1-style or node2-style signing/verification is used.

---

## 12. Important Design Observations

These are the things a reader should notice beyond the basic features.

### Observation 1 - This is not a clean minimal script

This file is a working project file, not a textbook example.  
It contains:

- active code
- experimental code
- legacy code
- commented examples

So when studying it, do not assume every function is part of the same active path.

### Observation 2 - Post-quantum methods are the active focus

The strongest active theme in this file is:

- **Falcon-1024** for signatures
- **ASCON-128** for authenticated encryption

This is why the file is named `LDA_PQ_security.py`.

### Observation 3 - CSV is the backbone of coordination

The file heavily depends on CSV files to pass information between steps.

This means:

- keys are generated in one call
- later calls retrieve those keys from CSV
- signatures/ciphertexts are also written back to CSV

### Observation 4 - Some sensitive material is stored plainly

Private keys, nonces, and secret values are written into CSV files in readable form such as hex strings.

That is convenient for experiments, but not ideal for production security.

### Observation 5 - Some encryption modes are not modern-best practice

The older/classical section uses `AES.MODE_ECB` in several places.

ECB works technically, but it is usually not recommended for real secure system design because it leaks patterns.  
The active ASCON path is stronger from a modern authenticated-encryption perspective.

---

## 13. Simple Mental Model

If you want the easiest way to remember this file, think of it like this:

### Layer 1 - Command parser

"What operation did the user ask for?"

### Layer 2 - Storage helpers

"Find or update the needed keys/results in CSV files."

### Layer 3 - Security engine

"Run Falcon signing/verification or ASCON encryption/decryption."

### Layer 4 - Role-based execution

"If this run is for the controller, do controller security tasks. If it is for a node, do node tasks."

---

## 14. What You Should Remember Most

If you only remember a few things from this file, remember these:

1. `LDA_PQ_security.py` is a command-driven security utility, not a single fixed workflow.
2. The two main active security methods are **Falcon-1024** and **ASCON-128**.
3. Falcon is used for **digital signatures**.
4. ASCON is used for **authenticated encryption**.
5. The file also contains classical methods like **RSA**, **AES**, **ECC/ECDH**, and **HMAC**, but much of that logic is in preserved/commented sections.
6. CSV files are central to how this script stores keys, signatures, ciphertext, and verification results.
7. The controller-side flow is the most important active path in the current file.

---

## Final Understanding in One Paragraph

`LDA_PQ_security.py` is a hybrid security script that mixes active post-quantum mechanisms with older classical security code. Its real active core is a controller-oriented workflow where command-line flags trigger operations like Falcon key generation, Falcon signing/verification, and ASCON key generation, encryption, and decryption. The rest of the file supports this with many CSV helper functions that store and retrieve keys and results. So the best way to understand the file is to see it as a practical experimental security manager whose main modern focus is **post-quantum signatures plus lightweight authenticated encryption**.

