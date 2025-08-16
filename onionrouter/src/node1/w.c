#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    int count;
    int key_len;
    char *key;
    char value[1024];
} DataRecord;

/*
mode: A string specifying the mode in which the file should be opened. Common modes include:

"r": Open for reading.
"w": Open for writing (truncates the file if it exists, creates it if it doesn't).
"a": Open for appending (writes at the end of the file, creates it if it doesn't exist).
"r+": Open for both reading and writing.
"w+": Open for both reading and writing (truncates or creates).
"a+": Open for both reading and appending.

Common fopen() modes for binary files:

"rb": Open for reading in binary mode. The file must exist.
"wb": Create an empty file for writing in binary mode. If the file exists, its contents are truncated (cleared).
"ab": Open for appending (writing at the end) in binary mode. If the file does not exist, it is created.
"r+b" or "rb+": Open for both reading and writing in binary mode. The file must exist.
"w+b" or "wb+": Create an empty file for both reading and writing in binary mode. If the file exists, its contents are truncated.
"a+b" or "ab+": Open for both reading and appending (writing at the end) in binary mode. If the file does not exist, it is created.
*/
void print_binary_as_table(const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        return;
    }

    printf("| %-25s | %-60s |\n", "Key", "Value");
    printf("|---------------------------|------------------------------------------------------------|\n");

    while (!feof(file))
    {
        DataRecord record;

        // Читаем количество записей
        if (fread(&record.count, sizeof(int), 1, file) != 1)
            break;

        // Читаем длину ключа
        if (fread(&record.key_len, sizeof(int), 1, file) != 1)
            break;

        // Выделяем память под ключ
        record.key = malloc(record.key_len + 1);

        // Читаем ключ
        if (fread(record.key, 1, record.key_len, file) != record.key_len)
        {
            free(record.key);
            break;
        }
        record.key[record.key_len] = '\0';

        // Читаем значение до конца строки
        int i = 0;
        char ch;
        while (fread(&ch, 1, 1, file) == 1 && ch != '\n' && i < 1023)
        {
            if (ch != '\r')
            { // Пропускаем CR
                record.value[i++] = ch;
            }
        }
        record.value[i] = '\0';

        printf("| %-25s | %-60s |\n", record.key, record.value);
        free(record.key);
    }

    fclose(file);
}

int main()
{
    print_binary_as_table("lsm_data.bin");
    return 0;
}