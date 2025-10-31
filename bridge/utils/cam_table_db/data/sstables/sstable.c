#include "lsm.h"
#include <dirent.h>

// Создает директорию для данных, если её нет
void ensure_data_dir()
{
    DIR *dir = opendir("data");
    if (!dir)
        mkdir("data", 0700);
    else
        closedir(dir);
}

// Новый формат имени файла
void generate_sstable_path(char *buf, size_t size, int level, int seq)
{
    snprintf(buf, size, "data/L%d-%05d.sst", level, seq);
}