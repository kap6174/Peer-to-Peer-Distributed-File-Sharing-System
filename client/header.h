#ifndef MY_FILE
#define MY_FILE
#include <vector>
#include <unordered_map>
#include <string>

using namespace std;

void parseFile(string file_path, int trackerNo, string &trackerIp, string &trackerPort);
vector<char *> split1(const char* str, const char* delim);
int getFileSize(string path);
unordered_map<int, int> pieceSelectionAlgorithm(unordered_map<int, string> clientswithfile);

#endif