#include <iostream>
#include <vector>
#include "header.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#define readsize 1000
using namespace std;



void parseFile(string file_path, int trackerNo, string &trackerIp, string &trackerPort){
    int file = open(file_path.c_str(), O_RDONLY);

    if(file < 0){
        cout << "File could not be opened" << endl;
        exit(EXIT_FAILURE);
    }
    char *content = (char*)calloc(readsize+1, sizeof(char));
    int size = read(file, content, readsize);

    string trackerInfo = string(content);

    vector<string> lines;
    stringstream ss(trackerInfo);
    string line;

    while(getline(ss, line, '\n')){
        lines.push_back(line);
    }

    if(trackerNo >= lines.size()){
        cout << "Input is wrong. Cannot process request. " << endl;
        exit(EXIT_FAILURE);
    }

    trackerIp = "";
    trackerPort = "";
    vector<char*>temp = split1(lines[trackerNo-1].c_str(), ":");
    trackerIp = temp[0];
    trackerPort = temp[1];
}