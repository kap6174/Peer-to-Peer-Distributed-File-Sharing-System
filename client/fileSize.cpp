#include <sys/stat.h>
#include <fcntl.h>
#include "header.h"
#include <iostream>
#include <string>

using namespace std;

int getFileSize(string path){
    struct stat file_stat;

    if(stat(path.c_str(), &file_stat) == -1){
        cerr << "File size cannot be shown" << endl;
        return -1;
    }

    return file_stat.st_size;
}