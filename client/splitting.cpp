#include <iostream>
#include <vector>
#include <cstring>
#include "header.h"
using namespace std;

vector<char *> split1(const char* str, const char* delim) {
    vector<char *> result;
    char* token = strtok(const_cast<char *>(str), delim);
    
    while (token != nullptr) {
        result.push_back(token);
        token = strtok(nullptr, delim);
    }
    return result;
}