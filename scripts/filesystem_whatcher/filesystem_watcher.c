#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_FILENAME_LENGTH 100
#define MAX_FILES 10000

typedef struct {
     uint8_t IV[16];                             /**< File -IV in case it is CSP, and setup cipher on */
    unsigned int offset;                        /**< Position in the file system, where the data related with the filename starts */
    uint32_t CRC_32_checksum;                   /**< Checksum for file integrity */
    size_t size;                                /**< Size of the data associated with the filename */
    size_t filename_length;                     /**< Parameter size */
    uint8_t isCSP;                              /**< Parameter to determine if it is CSP */
    unsigned char filename[MAX_FILENAME_LENGTH]; /**< Name of the file, supposed to be a string of max 50 size */
} FileAllocation;

typedef struct {
    unsigned int num_filenames;                  /**< Current num of descriptors of the file*/
    FileAllocation allocations[MAX_FILES];       /**< Array containing all the files in the file system*/
    FILE *FS_data_descriptor;                      /**< File with the stored data of all the file system*/
    unsigned char file_system_rpath[512];         /** relative path to the file storing all the data in the OS*/
    uint8_t filesystem_state;                     /** parameter to indicate if the filesystem is open or close */
    uint16_t filesystem_calls;                    /** number of stdin calls to fflush stdin */
    uint8_t cipher_mode;                          /** current mode of the file_system, should only be setup once */
} File_System;

File_System MetadataBlock;

void saveFileSystemPath(const char *path);
void printFiles();
void viewFileByIndex(int index);

int main() {
    char Absolute_Path[1024];
    char option;
    FILE *fileDescriptor;

    do {
        printf("Menú (introduce el número de la opción que deseas):\n");
        printf("1: si el filesystem_path ya está cargado previamente\n");
        printf("2: para introducir un nuevo path al filesystem\n");
        option = getchar();

        while (getchar() != '\n');  // Limpiar el buffer de entrada

        if (option == '1') {
            fileDescriptor = fopen("filesystem_path.txt", "r");
            if (!fileDescriptor || fgets(Absolute_Path, sizeof(Absolute_Path), fileDescriptor) == NULL) {
                perror("Error al leer la ruta del fichero\n");
                if (fileDescriptor) fclose(fileDescriptor);
                return 1;
            }
            fclose(fileDescriptor);
            char *newline = strchr(Absolute_Path, '\n');
            if (newline) {
                *newline = '\0';
            }
            break;
        } else if (option == '2') {
            printf("Introduce el path al filesystem desde el directorio actual: ");
            scanf("%1023s", Absolute_Path);
            saveFileSystemPath(Absolute_Path);
            break;
        } else {
            printf("Opción no válida, introduce un 1 o un 2\n");
        }
    } while (1);

    MetadataBlock.FS_data_descriptor = fopen(Absolute_Path, "r");
    if (MetadataBlock.FS_data_descriptor == NULL) {
        perror("Ruta actual al sistema de ficheros no válida!\n");
        return 2;
    }

    if (fread(&MetadataBlock, sizeof(MetadataBlock), 1, MetadataBlock.FS_data_descriptor) != 1) {
        perror("Error al leer los metadatos del filesystem!\n");
        return 3;
    }
    MetadataBlock.FS_data_descriptor = fopen(Absolute_Path, "r");
    int index;
    do {
        printFiles();
        printf("Selecciona el índice del archivo a leer o -1 para salir: ");
        scanf("%d", &index);
        if (index == -1) break;
        viewFileByIndex(index);
    } while (1);

    fclose(MetadataBlock.FS_data_descriptor);
    return 0;
}

void saveFileSystemPath(const char *path) {
    FILE *file = fopen("filesystem_path.txt", "w");
    if (file == NULL) {
        perror("Failed to open file to save path");
        return;
    }
    fprintf(file, "%s\n", path);
    fclose(file);
}

void printFiles() {
    printf("File System Contents:\n\n");
    for (int i = 0; i < MetadataBlock.num_filenames; i++) {
        printf("%d: %s | Offset: %u | Size: %lu bytes | CRC: %u\n", i, MetadataBlock.allocations[i].filename, MetadataBlock.allocations[i].offset, MetadataBlock.allocations[i].size, MetadataBlock.allocations[i].CRC_32_checksum);
    }
    printf("\n");
}

void viewFileByIndex(int index) {
    if (index < 0 || index >= MetadataBlock.num_filenames) {
        printf("Índice inválido.\n");
        return;
    }

    FileAllocation file = MetadataBlock.allocations[index];

    printf("¿Cómo quieres ver el archivo? (A para ASCII, H para Hexadecimal): ");
    char format;
    scanf(" %c", &format);  // Ensure the buffer is clean before reading the format.

    fseek(MetadataBlock.FS_data_descriptor, sizeof(MetadataBlock) + file.offset, SEEK_SET);  // Position the file descriptor at the beginning of the file data.

    unsigned char *data = malloc(file.size);
    if (!data) {
        perror("No se pudo asignar memoria para los datos del archivo\n");
        return;
    }

    if (fread(data, 1, file.size, MetadataBlock.FS_data_descriptor) != file.size) {
        free(data);
        perror("Error al leer los datos del archivo\n");
        return;
    }

    // Create a temporary file to store the data
    char tempFilePath[256];
    snprintf(tempFilePath, sizeof(tempFilePath), "/tmp/temp_file_%d", index);
    FILE *tempFile = fopen(tempFilePath, "wb");
    if (!tempFile) {
        free(data);
        perror("No se pudo crear el archivo temporal\n");
        return;
    }
    fwrite(data, 1, file.size, tempFile);
    fclose(tempFile);
    free(data);

    // Construct the command to view the file
    char command[1024];
    if (format == 'H' || format == 'h') {
        snprintf(command, sizeof(command), "xxd %s | less", tempFilePath);
    } else if (format == 'A' || format == 'a') {
        snprintf(command, sizeof(command), "less %s", tempFilePath);
    } else {
        printf("Formato no reconocido. Use 'A' para ASCII o 'H' para Hexadecimal.\n");
        remove(tempFilePath);
        return;
    }

    system(command);  // Execute the system command to display the file.

    // Clean up the temporary file after viewing
    remove(tempFilePath);
}



