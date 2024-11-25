#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // Para usar 'fork' y 'execlp'


// Archivos de cabecera para criptografía
#include "../../crypto/ECDSA_256.h"
#include "../../crypto/SHA256.h"
#include "../../prng/random_number.h"

//gcc key_and_cert_creator.c ../../prng/random_number.c ../../crypto/ECDSA_256.c  ../../crypto/SHA256.c -o key_cert_generator

// Función para leer un archivo y devolver su contenido como un arreglo
char *read_file_to_array(const char *filename, size_t *file_size)
{
	// Abrir el archivo en modo lectura binaria
	FILE *file = fopen(filename, "rb");
	if (file == NULL)
	{
		perror("Error al abrir el archivo");
		return NULL; // Devolver NULL si no se puede abrir el archivo
	}

	// Mover el puntero del archivo al final para obtener el tamaño del archivo
	fseek(file, 0, SEEK_END);
	*file_size = ftell(file); // Obtener el tamaño del archivo
	fseek(file, 0, SEEK_SET); // Restablecer el puntero del archivo al inicio

	// Asignar memoria para el arreglo
	char *buffer = (char *)malloc(*file_size);
	if (buffer == NULL)
	{
		perror("Error al asignar memoria");
		fclose(file);
		return NULL; // Devolver NULL si falla la asignación de memoria
	}

	// Leer el contenido del archivo en el arreglo
	size_t bytes_read = fread(buffer, 1, *file_size, file);
	if (bytes_read != *file_size)
	{
		perror("Error al leer el archivo");
		free(buffer);
		fclose(file);
		return NULL; // Devolver NULL si falla la lectura
	}

	// Cerrar el archivo
	fclose(file);
	return buffer; // Devolver el buffer con el contenido del archivo
}

// Función para mostrar el contenido de un archivo en hexadecimal
void watch_hex_file(const char *filename)
{
	// Crear un proceso hijo para ejecutar 'less' con 'hexdump'
	if (fork() == 0)
	{
		execlp("hexdump", "hexdump", "-C", filename, (char *)NULL);
		perror("Error al ejecutar hexdump");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Uso: %s <opción> [filepath]\n", argv[0]);
		printf("Opciones:\n");
		printf("  -ek <filepath> for generate an ecdsa key pair\n");
		printf("  -cg <key_filepath> <file_tosign> <keycert_name> for create a new certificate given a keypair and a file\n");
		printf("  -ap <cert_file> <file_to_apply> to apply a certificate to a file\n");
		printf("  -wh <file> to what a cert file in hex\n"); 
		return 1;
	}

	// Opción para mostrar el archivo en hexadecimal
	if (strcmp(argv[1], "wh") == 0)
	{
		if (argc < 3)
		{
			printf("Error: Falta el archivo para la opción -watchhexfile.\n");
			return 1;
		}
		watch_hex_file(argv[2]);
		return 0;
	}

	// Opción para generar un par de claves ECDSA
	if (strcmp(argv[1], "-ek") == 0)
	{
		if (argc < 3)
		{
			printf("Error: Falta filepath para la opción -ecdsa_keypargen.\n");
			return 1;
		}
		unsigned char private_key[32];
		unsigned char public_key[33];
		ecc_make_key(public_key, private_key);
		FILE *f = fopen(argv[2], "wb");
		fwrite(private_key, sizeof(private_key), 1, f);
		fwrite(public_key, sizeof(public_key), 1, f);
		fclose(f);
	}
	// Opción para generar un certificado
	else if (strcmp(argv[1], "-cg") == 0)
	{
		if (argc < 5)
		{
			printf("Error: Falta información para la opción -cert_gen.\n");
			return 1;
		}

		unsigned char key_AES256_certificate[129];
		unsigned char ecdsa_keypar[65];
		unsigned char hash[32];
		size_t file_size;

		// Llenar el buffer con bytes aleatorios
		API_RNG_fill_buffer_random(key_AES256_certificate, 32);

		// Leer la clave ECDSA del archivo
		FILE *f1 = fopen(argv[2], "rb");
		fread(ecdsa_keypar, sizeof(ecdsa_keypar), 1, f1);
		fclose(f1);

		// Leer el archivo a firmar
		unsigned char *buffer_to_sign = read_file_to_array(argv[3], &file_size);
		if (buffer_to_sign == NULL)
		{
			return 1; // Manejar error de lectura
		}

		// Calcular el hash y firmar
		API_sha256(buffer_to_sign, file_size, hash);
		ecdsa_sign(ecdsa_keypar, hash, key_AES256_certificate + 32);
		memcpy(key_AES256_certificate + 96, ecdsa_keypar + 32, 33); // Copiar la clave pública

		// Guardar el certificado
		f1 = fopen(argv[4], "wb");
		fwrite(key_AES256_certificate, sizeof(key_AES256_certificate), 1, f1);
		fclose(f1);

		// Liberar memoria
		free(buffer_to_sign);
	}
	else if (strcmp(argv[1], "-ap") == 0){
		if (argc < 4)
		{
			printf("Error: Falta informacion para validar un cert a un fichero\n");
			return 1;
		}
		unsigned char key_AES256_certificate[129];
		unsigned char hash[32];
		size_t file_size;

		// Leer el archivo a firmar
		unsigned char *buffer_to_sign = read_file_to_array(argv[3], &file_size);
		if (buffer_to_sign == NULL)
		{
			return 1; // Manejar error de lectura
		}
		API_sha256(buffer_to_sign, file_size, hash);
		FILE *f = fopen(argv[2],"rb");
		fread(key_AES256_certificate,sizeof(key_AES256_certificate),1,f);
		fclose(f);
		int result = API_ecdsa_verify(key_AES256_certificate + 96,hash,key_AES256_certificate + 32);
		if(result == 1){
			printf("certificado validado correctamente\n");
		}
		else{
			printf("certificado no validado!\n");
		}
	}
	else
	{
		printf("Opción inválida: %s\n", argv[1]);
		return 1;
	}

	return 0;
}
