# Common Cryptographic Library

## Name
Development of a certifiable EAL2 cryptographic module following the design guidelines of the FIPS standards (This does not mean that the module is certified, nor that it has any guarantee, as I do not have the time or the money to go through this certification.).

## Description
The objective of this project is threefold. First, it aims to serve as a foundational project for my Bachelor’s Thesis (TFG) in the field of Software Engineering. Second, it seeks to enhance my programming skills, particularly in the domain of cryptography. Third, and most importantly, this endeavor is designed to develop a functional cryptographic module capable of securely encrypting and authenticating data packets in compliance with FIPS standards, the subsystems that compose the module are as independent between them as possible, so they cant be taken out, and implemented in othe software.

The module is intended to operate efficiently within a constrained memory footprint while ensuring rapid processing speeds. It is also designed to be user-friendly, allowing individuals with minimal technical expertise to implement it freely in their own applications for the purpose of encrypting and authenticating data packets.

To facilitate understanding, the code is thoroughly documented, ensuring that anyone with basic programming knowledge can comprehend its functionality and the rationale behind its implementation. This comprehensive approach not only fosters learning but also encourages widespread adoption of cryptographic practices in software development.

## Installation
The module can be compiled in two distinct ways: as code directly injected into a code repository or as a static library. The Makefile includes the necessary commands to accomplish both tasks.

```bash
make testing_cryptomodule
```

This command compiles the code and generates a small test version based on the functions defined in the file Code_testing.c. (intended for inmmediate easy tests),

```bash
make static_lib
```

This command creates a static library of the code within the XLibrary_crypto directory, along with the API for the callable functions. It is important to note that this code will NOT be functional at this stage, as it will be necessary to generate a certificate for the binary before it can operate effectively, this certificate must sign both the binary of the static library that implements the functionality of the cryptographic module and the binary of the program that uses the static library. For this reason a certificate is associated with a binary that uses the library.  (there is a script in the directory utils/certificate_manager for generate a certificate). Subsequently, this certificate must be loaded into the cryptographic module in the initialization. 

## Usage
Only the functions within API_core.h should be called from outside the module. The first step is to initialize the module with a valid cryptographic certificate (a script for creating certificates, is available in utils/certificate_manager) and specify the desired name for the data file by invoking the following function:

```c
API_MC_Initialize_module(unsigned char *KEK_CERTIFICATE_file, unsigned char *Cryptodata_filename);
```

After initialization, if all required tests are passed and the certificates are validated, the module will enter the operational state. In this state, the following actions can be performed:

Get the current state of the cryptomodule:
```c
int API_MC_getcurrent_state();
```

Introduce 256-bit keys using:
```c
API_MC_Insert_Key(uint8_t In_Key[32], size_t key_size, unsigned char *Key_id, size_t Key_id_length);
```

Delete 256-bit keys using:
```c
API_MC_Delete_Key(unsigned char *Key_id, size_t Key_id_length);
```

Load a key from the data system for use with:
```c
API_MC_Load_Key(unsigned char *Key_id, size_t Key_id_length);
```

Generate Pseudorandom numbers:
```c
int API_MC_fill_buffer_random(unsigned char *buffer, size_t size);
```

Sign and encrypt a data packet with:
```c
API_MC_Sing_Cipher_Packet(unsigned char *data_in, size_t data_size, unsigned char *packet_out, size_t *packet_out_length);
```

Decrypt and authenticate a data packet with:
```c
int API_MC_Decipher_Auth_Packet(unsigned char *data_in, size_t data_in_length, unsigned char *out_data, size_t *out_data_length);
```

Safely shut down the module with:
```c
int API_MC_Shutdown_module();
```

The code is thoroughly documented, so for any doubts, please refer to the comments in the header files and within the code itself.

It is important to note that incorrect use of the module as a client (e.g., improper key management or misuse of the module) could compromise its security or trigger a defense mechanism, causing the module to zeroize. If used in production environments, it is strongly recommended to acknowledge that this module has been developed by a single individual and has not undergone formal certification. Although it has been designed with certification in mind, I neither have the financial resources to submit it to a certification body nor the time to undergo the full certification process.

## Authors and acknowledgment
All the code, except for the ECDSA256_secpk algorithm, has been programmed from scratch by myself. The effort has been substantial, as it was undertaken by a single individual. I hope to continue improving the module in the future, with the goal of enhancing its capabilities and even adding new functionalities.

## License
This project is licensed under the terms of the GNU Lesser General Public License (LGPL) version 2.1.

You are free to use, modify, and distribute the software, provided that modifications and derivative works are also licensed under the LGPL. The full terms of the license can be found in the LICENSE file or at the official GNU website:
https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html


