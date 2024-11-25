/**
 * @file log_manager.c
 * @brief File containing all the logfile management functions
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/
#include "log_manager.h"

sem_t TraceSem_empty;
sem_t TraceSem_full;

pthread_mutex_t traceMutex = PTHREAD_MUTEX_INITIALIZER;

int important_trace = 0;
unsigned char concatenated_string[MAX_STRING];

/****************************************************************************************************************
 * Function definition zone
 ****************************************************************************************************************/

int API_LT_startTraceFile()
{
    int create1, create2;
    pthread_t thread_trace;
    // Inicialización del sistema de archivos con datos designados
    unsigned char content[MAX_BYTES_TRACER_LOW] = {0x00, 0x00, 0x00, 0x05};
    unsigned char content2[MAX_BYTES_TRACER_HIGH] = {0x00, 0x00, 0x00, 0x05};

    create1 = API_FS_create_file_data(TRACERLOW, TRACERLOW_LENGTH, content, MAX_BYTES_TRACER_LOW, NOT_CSP);
    create2 = API_FS_create_file_data(TRACERHIGH, TRACERHIGH_LENGTH, content2, MAX_BYTES_TRACER_HIGH, NOT_CSP);
    pthread_create(&thread_trace, NULL, WriteTrace, NULL);
    sem_init(&TraceSem_empty, 0, 1);
    sem_init(&TraceSem_full, 0, 0); // Cambiado a 0 para que empiece vacío
    return (create1 == FILESYSTEM_OK && create2 == FILESYSTEM_OK) || 
           (create1 == FS_FILENAME_ALREADYEXIST_ERROR && create2 == FS_FILENAME_ALREADYEXIST_ERROR) ? TRACER_OK : LT_TRACER_ERROR;
}

void API_LT_traceWrite(unsigned char *str, ...) {
    sem_wait(&TraceSem_empty); // Espera hasta que haya espacio disponible

    va_list args;
    va_start(args, str);
    unsigned char *current_arg = str;
    int total_length = 0;
    int current_arg_length;
    int arg_count = 1; // Inicia en 1 para contar el primer argumento 'str'
    int count = 0;

    // Concatenar y contar argumentos
    do {
        current_arg_length = strlen(current_arg);
        total_length += current_arg_length + 1; // +1 por el espacio o el '\0'
        current_arg = va_arg(args, unsigned char *);
        if (current_arg != NULL) {
            arg_count++;
            count++;
        }
    } while (current_arg != NULL && count <= MAX_ARGUMENTS);

    va_end(args);
    total_length++; // Para el carácter de nueva línea

    // Verificación del tamaño máximo
    if (total_length + 20 > MAX_STRING) { // 20 para la fecha y un espacio
        sem_post(&TraceSem_empty);
        return; // Salir si el tamaño excede el máximo permitido
    }

    // Construcción del mensaje de traza
    pthread_mutex_lock(&traceMutex);
    concatenated_string[0] = '\0';
    unsigned char time[20];
    MT_getTime(time);
    snprintf(concatenated_string, MAX_STRING, "%s %s", time, str);

    va_start(args, str);
    current_arg = va_arg(args, unsigned char *);
    while (current_arg != NULL) {
        strncat(concatenated_string, " ", MAX_STRING - strlen(concatenated_string) - 1);
        strncat(concatenated_string, current_arg, MAX_STRING - strlen(concatenated_string) - 1);
        current_arg = va_arg(args, unsigned char *);
    }
    strncat(concatenated_string, "\n", MAX_STRING - strlen(concatenated_string) - 1);
    va_end(args);

    important_trace = (arg_count > 1) ? 1 : 0;

    pthread_mutex_unlock(&traceMutex);
    sem_post(&TraceSem_full); // Notifica al hilo de escritura que hay nuevos datos
}

void *WriteTrace(void *arg) {
    while (1) {
        sem_wait(&TraceSem_full); // Espera hasta que hay un mensaje disponible
        pthread_mutex_lock(&traceMutex);

        unsigned char File_size_char[4];
        unsigned int Tracer_file_size;
        unsigned int current_offset;

        // Escribe en TRACERLOW siempre
        API_FS_read_buffer_from_file(TRACERLOW, TRACERLOW_LENGTH, File_size_char, sizeof(unsigned int), 0);
        Tracer_file_size = (File_size_char[0] << 24) | (File_size_char[1] << 16) | (File_size_char[2] << 8) | (File_size_char[3]);
        current_offset = Tracer_file_size + strlen(concatenated_string);

        // Manejo de sobrepaso
        if (current_offset > MAX_BYTES_TRACER_LOW) {
            current_offset = 5 + strlen(concatenated_string);
            API_FS_write_buffer_to_file(TRACERLOW, TRACERLOW_LENGTH, concatenated_string, strlen(concatenated_string), Tracer_file_size);
        } else {
            API_FS_write_buffer_to_file(TRACERLOW, TRACERLOW_LENGTH, concatenated_string, strlen(concatenated_string), Tracer_file_size);
        }

        // Actualizar el tamaño del archivo
        File_size_char[3] = current_offset;
        File_size_char[2] = current_offset >> 8;
        File_size_char[1] = current_offset >> 16;
        File_size_char[0] = current_offset >> 24;
        API_FS_write_buffer_to_file(TRACERLOW, TRACERLOW_LENGTH, File_size_char, sizeof(current_offset), 0);

        // Si important_trace es verdadero, también escribe en TRACERHIGH
        if (important_trace) {
            API_FS_read_buffer_from_file(TRACERHIGH, TRACERHIGH_LENGTH, File_size_char, sizeof(unsigned int), 0);
            Tracer_file_size = (File_size_char[0] << 24) | (File_size_char[1] << 16) | (File_size_char[2] << 8) | (File_size_char[3]);
            current_offset = Tracer_file_size + strlen(concatenated_string);

            // Manejo de sobrepaso en TRACERHIGH
            if (current_offset > MAX_BYTES_TRACER_HIGH) {
                current_offset = 5 + strlen(concatenated_string);
                API_FS_write_buffer_to_file(TRACERHIGH, TRACERHIGH_LENGTH, concatenated_string, strlen(concatenated_string), 5);
            } else {
                API_FS_write_buffer_to_file(TRACERHIGH, TRACERHIGH_LENGTH, concatenated_string, strlen(concatenated_string), Tracer_file_size);
            }

            // Actualizar el tamaño del archivo
            File_size_char[3] = current_offset;
            File_size_char[2] = current_offset >> 8;
            File_size_char[1] = current_offset >> 16;
            File_size_char[0] = current_offset >> 24;
            API_FS_write_buffer_to_file(TRACERHIGH, TRACERHIGH_LENGTH, File_size_char, sizeof(current_offset), 0);
            important_trace = 0; // Reiniciar la bandera
        }

        pthread_mutex_unlock(&traceMutex);
        sem_post(&TraceSem_empty); // Libera el espacio
    }
    return NULL;
}

void MT_getTime(unsigned char *aux)
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    snprintf(aux, 20, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
