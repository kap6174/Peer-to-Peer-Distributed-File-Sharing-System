#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <unistd.h>
#include "header.h"
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <mutex>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <queue>
#include <condition_variable>

using namespace std;

// --- Global variables for session and connection state ---
string currentUser = "";
string currentPassword = "";
bool isLoggedIn = false;
vector<pair<string, int>> sharedFiles; // filepath, groupId
vector<pair<string, int>> g_trackers; // Global tracker list
int g_client_socket = -1; // Global socket for reconnection
int globalStoreClientPort;


string hashfunc(const char* data, size_t len, bool full_hash = false){
    unsigned char hash[SHA_DIGEST_LENGTH]; // 20 bytes for SHA1
    SHA1(reinterpret_cast<const unsigned char*>(data), len, hash);

    ostringstream oss;
    // Per requirement, piecewise hash is first 20 chars of full hash. Full hash is all 40.
    int hash_len = full_hash ? SHA_DIGEST_LENGTH : 20;
    for(int i = 0; i < hash_len; i++){
        oss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

#define BUFFER_SIZE 8192
#define PIECE_SIZE 524288 // 512KB
#define NO_OF_THREADS 10

vector<string> split(const string& s, const string& delimiter) {
    vector<string> tokens;
    string temp_s = s;
    size_t pos = 0;
    string token;
    while ((pos = temp_s.find(delimiter)) != string::npos) {
        token = temp_s.substr(0, pos);
        if (!token.empty()) tokens.push_back(token);
        temp_s.erase(0, pos + delimiter.length());
    }
    if (!temp_s.empty()) tokens.push_back(temp_s);
    return tokens;
}

string receiveResponse(int client_socket){
    char buffer[BUFFER_SIZE] = {0};
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) return "";
    return string(buffer, bytes_read);
}

static inline string trim(string s) {
    s.erase(s.begin(), find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    s.erase(find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !isspace(ch);
    }).base(), s.end());
    return s;
}

// --- P2P Data Structures and Logic ---
mutex file_mutex;

struct Task{
    int pieceNumber;
    int clientPort;
    string filename;
    string downloadfilePath;
    int filesize;
    int numberOfPieces;
    string hash_manifest;
};

queue<Task> taskQueue;
mutex mutexfortaskQueue;
condition_variable conditionfortaskQueue;
bool done = false;

class FileData{
    public:
    string pieceMatrix;
    string filepath;
    string downloadfilePath;
    int groupid;
    int size;
    int numberOfPieces;
    string filename;

    FileData(int s, int g, int n, string f_path, string f_name){
        size = s;
        groupid = g;
        numberOfPieces = n;
        filepath = f_path;
        filename = f_name;
        pieceMatrix = string(n, '0');
    }
    
    void set_as_seeder(){
        pieceMatrix = string(numberOfPieces, '1');
    }

    void updatepiece(int piecenumber){
        if (piecenumber >= 0 && (size_t)piecenumber < pieceMatrix.length()) {
            file_mutex.lock();
            pieceMatrix[piecenumber] = '1';
            file_mutex.unlock();
        }
    }
};

unordered_map<string, FileData*> filedetails;
unordered_map<int, string> clientswithfile;

void parseInput(string temp, string& ipClient, string& portStr){
    size_t colon_pos = temp.find(':');
    if (colon_pos != string::npos) {
        ipClient = temp.substr(0, colon_pos);
        portStr = temp.substr(colon_pos + 1);
    }
}

string askFileDetails(int otherClientPort, string filename){
    string ip = "127.0.0.1";
    int client_socket = 0;
    struct sockaddr_in address;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket == 0) return "";

    address.sin_family = AF_INET;
    address.sin_port = htons(otherClientPort);

    if(inet_pton(AF_INET, ip.c_str(), &address.sin_addr) <= 0){
        close(client_socket);
        return "";
    }

    if(connect(client_socket, (struct sockaddr*)&address, sizeof(address)) < 0){
        cerr << "Connection to peer " << otherClientPort << " failed" << endl;
        close(client_socket);
        return "";
    }

    string rp = "getfiledetails " + filename + "\n";
    send(client_socket, rp.c_str(), rp.size(), 0);
    string res = receiveResponse(client_socket);
    close(client_socket);
    return res;
}

void listeningthread(int my_server_socket, sockaddr_in address){
    if(listen(my_server_socket, 10) < 0){
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    cout << "Peer listening started on port " << globalStoreClientPort << endl;
    while(true){
        int addrlen = sizeof(address);
        int client_socket = accept(my_server_socket, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_socket < 0) { continue; }

        char buffer[BUFFER_SIZE] = {0};
        int tempval = read(client_socket, buffer, BUFFER_SIZE - 1);
        if(tempval > 0){
            string message = trim(string(buffer, tempval));
            vector<string> messageparsed = split(message, " ");

            if(messageparsed.empty()) { close(client_socket); continue; }

            string command = messageparsed[0];
            if(command == "getfiledetails"){
                if (messageparsed.size() < 2) { close(client_socket); continue; }
                string filename = messageparsed[1];
                if (filedetails.count(filename)) {
                    string sendMatrix = filedetails[filename]->pieceMatrix;
                    sendMatrix += " " + to_string(filedetails[filename]->size) + "\n";
                    send(client_socket, sendMatrix.c_str(), sendMatrix.size(), 0);
                }
            }
            else if(command == "getpiece"){
                if (messageparsed.size() < 3) { close(client_socket); continue; }
                string filename = messageparsed[1];
                int piecenumber = stoi(messageparsed[2]);

                if(filedetails.count(filename)){
                    FileData *filedata = filedetails[filename];
                    
                    if (piecenumber >= 0 && (size_t)piecenumber < filedata->pieceMatrix.length() && filedata->pieceMatrix[piecenumber] == '1') {
                        int totalFileSize = filedata->size;
                        int numberOfPieces = filedata->numberOfPieces;
                        
                        int piecesize = (piecenumber == numberOfPieces - 1 && totalFileSize % PIECE_SIZE != 0) 
                                        ? totalFileSize % PIECE_SIZE 
                                        : PIECE_SIZE;

                        int offset = piecenumber * PIECE_SIZE;
                        
                        // A seeder uses filepath, a leecher uses downloadfilepath
                        const char* path_to_read = !filedata->filepath.empty() ? filedata->filepath.c_str() : filedata->downloadfilePath.c_str();
                        int filefd = open(path_to_read, O_RDONLY);

                        if(filefd != -1) {
                            char piecehold[piecesize];
                            lseek(filefd, offset, SEEK_SET);
                            ssize_t bytesread = read(filefd, piecehold, piecesize);
                            close(filefd);

                            if(bytesread > 0) {
                                send(client_socket, piecehold, bytesread, 0);
                            }
                        }
                    }
                }
            }
        }
        close(client_socket);
    }
}


void parallelDownload(Task task){
    string ip = "127.0.0.1";
    int client_client_socket = 0;
    
    struct sockaddr_in address;
    client_client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_client_socket == 0) return;

    address.sin_family = AF_INET;
    address.sin_port = htons(task.clientPort);
    if(inet_pton(AF_INET, ip.c_str(), &address.sin_addr) <= 0){
        close(client_client_socket);
        return;
    }

    if(connect(client_client_socket, (struct sockaddr*)&address, sizeof(address)) < 0){
        close(client_client_socket);
        return;
    }

    string request = "getpiece " + task.filename + " " + to_string(task.pieceNumber) + "\n";
    send(client_client_socket, request.c_str(), request.size(), 0);
    
    int filefd = open(task.downloadfilePath.c_str(), O_WRONLY, 0644);
    if (filefd == -1) {
        close(client_client_socket);
        return;
    }

    char buffer[PIECE_SIZE];
    ssize_t bytesReceived;
    long total = 0;
    off_t offset = (off_t)task.pieceNumber * PIECE_SIZE;

    int piecesize = (task.pieceNumber == task.numberOfPieces - 1 && task.filesize % PIECE_SIZE != 0) 
                    ? task.filesize % PIECE_SIZE
                    : PIECE_SIZE;
    
    string piece_data;
    piece_data.reserve(piecesize);

    while (total < piecesize) {
        bytesReceived = read(client_client_socket, buffer, min((long)sizeof(buffer), (long)(piecesize - total)));
        if(bytesReceived <= 0) break;
        piece_data.append(buffer, bytesReceived);
        total += bytesReceived;
    }
    close(client_client_socket);
    
    string newhash = hashfunc(piece_data.data(), piece_data.size());
    string authoritative_hash = task.hash_manifest.substr(task.pieceNumber * 40, 40);
    
    if(newhash == authoritative_hash){
        cout << "Piece " << task.pieceNumber << ": Hash matched." << endl;
        file_mutex.lock();
        lseek(filefd, offset, SEEK_SET);
        write(filefd, piece_data.data(), piece_data.size());
        file_mutex.unlock();

        if (filedetails.count(task.filename)) {
            filedetails[task.filename]->updatepiece(task.pieceNumber);
        }
    } else {
        cout << "Piece " << task.pieceNumber << ": HASH MISMATCH. Discarding piece." << endl;
    }
    close(filefd);
}


void workerThread(){
    while(true){
        Task task;
        {
            unique_lock<mutex> lock(mutexfortaskQueue);
            conditionfortaskQueue.wait(lock, []{return !taskQueue.empty() || done; });

            if(done && taskQueue.empty()) break;
            if (taskQueue.empty()) continue;

            task = taskQueue.front();
            taskQueue.pop();
        }
        parallelDownload(task);
    }
}

int connectToTracker(int& client_socket) {
    for (const auto& tracker : g_trackers) {
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) continue;

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(tracker.second);
        if (inet_pton(AF_INET, tracker.first.c_str(), &serv_addr.sin_addr) <= 0) {
            close(client_socket);
            continue;
        }

        if (connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) >= 0) {
            cout << "Connected to tracker at " << tracker.first << ":" << tracker.second << endl;
            return 0;
        }
        close(client_socket);
    }
    return -1;
}

void restoreSessionState(int client_socket) {
    if (!currentUser.empty() && !currentPassword.empty()) {
        cout << "Attempting to restore session for user: " << currentUser << endl;
        string loginCmd = "login " + currentUser + " " + currentPassword;
        send(client_socket, (loginCmd + "\n").c_str(), loginCmd.size() + 1, 0);
        string response = receiveResponse(client_socket);
        cout << "Re-login response: " << response;

        if (response.find("Welcome") != string::npos) {
            isLoggedIn = true;
            cout << "Session restored successfully." << endl;

            string portCmd = "port " + to_string(globalStoreClientPort);
            send(client_socket, (portCmd + "\n").c_str(), portCmd.size() + 1, 0);
            cout << "Re-sent listening port: " << globalStoreClientPort << endl;

            for (const auto& file : sharedFiles) {
                ifstream file_stream(file.first, ifstream::binary);
                if (file_stream) {
                    string full_file_content((istreambuf_iterator<char>(file_stream)), istreambuf_iterator<char>());
                    string complete_hash = hashfunc(full_file_content.c_str(), full_file_content.length(), true);
                    file_stream.clear();
                    file_stream.seekg(0);

                    char buffer[PIECE_SIZE];
                    string concatenated_hashes = "";
                    while(file_stream.read(buffer, PIECE_SIZE) || file_stream.gcount() > 0) {
                        concatenated_hashes += hashfunc(buffer, file_stream.gcount());
                    }
                    file_stream.close();
                    
                    vector<char*> fileparse = split1(file.first.c_str(), "/");
                    string filename = string(fileparse.back());
                    string uploadCmd = "upload_file " + filename + " " + to_string(file.second) + " " + concatenated_hashes + " " + complete_hash;
                    send(g_client_socket, (uploadCmd + "\n").c_str(), uploadCmd.size() + 1, 0);
                    receiveResponse(g_client_socket);
                    cout << "Re-announced file: " << filename << endl;
                }
            }
        } else {
            cout << "Failed to restore session. Please login again." << endl;
            isLoggedIn = false; currentUser = ""; currentPassword = "";
        }
    }
}

void handleCommand(string line) {
    string line_backup = line;
    vector<string> inputs = split(line_backup, " ");
    if (inputs.empty()) return;
    string command = inputs[0];

    if (command == "download_file") {
        if (inputs.size() < 4) { cout << "Usage: download_file <group_id> <file_name> <destination_path>" << endl; return; }
        int groupid = stoi(inputs[1]);
        string filename = trim(inputs[2]);
        string downloadfilepath = trim(inputs[3]);

        string toTracker = "download_file " + to_string(groupid) + " " + filename + "\n";
        send(g_client_socket, toTracker.c_str(), toTracker.size(), 0);
        
        string response = receiveResponse(g_client_socket);
        vector<string> response_parts = split(response, "|");
        if (response_parts.size() < 3) { cout << "Error: Invalid response from tracker: " << response << endl; return; }
        
        string port_str = response_parts[0];
        string piecewise_hash_manifest = response_parts[1];
        string complete_hash_manifest = trim(response_parts[2]);

        vector<string> portstr_vec = split(trim(port_str), " ");
        vector<int> ports;
        for(const auto& p_str : portstr_vec){
            if (!p_str.empty()) {
                int port = stoi(p_str);
                if(port != globalStoreClientPort) ports.push_back(port);
            }
        }
        if (ports.empty()) { cout << "No peers found sharing the file." << endl; return; }
        
        cout<< "Found " << ports.size() << " peers sharing the file." << endl;
        
        int filesize = 0;
        clientswithfile.clear();
        for(int port : ports){
            string res = askFileDetails(port, filename);
            if (res.empty()) continue;
            vector<string>parse = split(res, " ");
            if (parse.size() < 2) continue;
            filesize = stoi(trim(parse[1]));
            clientswithfile[port] = trim(parse[0]);
        }
        if (filesize == 0) { cout << "Could not retrieve file details from any peer." << endl; return; }

        int numberOfPieces = (filesize + PIECE_SIZE - 1) / PIECE_SIZE;
        cout << "File Size: " << filesize << " bytes, Pieces: " << numberOfPieces << endl;
        
        unordered_map<int, int> umap = pieceSelectionAlgorithm(clientswithfile);

        int filefd = open(downloadfilepath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if(filefd != -1) {
            ftruncate(filefd, filesize);
            close(filefd);
        } else {
             perror("Destination file could not be created");
             return;
        }

        cout << "Starting download..." << endl;
        FileData *f = new FileData(filesize, groupid, numberOfPieces, downloadfilepath, filename);
        filedetails[filename] = f;
        
        done = false;
        vector<thread> threads;
        for(int i = 0; i < NO_OF_THREADS; i++) threads.emplace_back(workerThread);

        {
            lock_guard<mutex> lock(mutexfortaskQueue);
            for(auto const& [pieceNum, clientPort] : umap){
                Task task;
                task.pieceNumber = pieceNum; task.clientPort = clientPort;
                task.filename = filename; task.downloadfilePath = downloadfilepath;
                task.filesize = filesize; task.numberOfPieces = numberOfPieces;
                task.hash_manifest = piecewise_hash_manifest;
                taskQueue.push(task);
            }
        }
        conditionfortaskQueue.notify_all();

        while(true) {
            unique_lock<mutex> lock(mutexfortaskQueue);
            if (taskQueue.empty()) break;
            lock.unlock(); this_thread::sleep_for(chrono::milliseconds(100));
        }
        done = true;
        conditionfortaskQueue.notify_all();

        for(auto& th : threads) if(th.joinable()) th.join();
        cout << "Download completed for: " << filename << endl;
        return;
    } else if (command == "show_downloads") {
        cout << "--- Download Status ---" << endl;
        for(auto const& [filename, data] : filedetails){
            int downloaded_pieces = 0;
            for(char c : data->pieceMatrix) {
                if (c == '1') downloaded_pieces++;
            }
            if (downloaded_pieces == data->numberOfPieces) {
                cout << "[C] " << data->groupid << " " << filename << endl;
            } else {
                cout << "[D] " << data->groupid << " " << filename << endl;
            }
        }
        return;
    } 
    
    // START: ADDED stop_share IMPLEMENTATION
    else if (command == "stop_share") {
        if (inputs.size() < 3) {
            cout << "Usage: stop_share <group_id> <file_name>" << endl;
            return;
        }
        string group_id_str = inputs[1];
        string filename = inputs[2];

        // The tracker expects "stop_share <filename> <groupid>"
        string stopCmd = "stop_share " + filename + " " + group_id_str;
        send(g_client_socket, (stopCmd + "\n").c_str(), stopCmd.size() + 1, 0);
        string response = receiveResponse(g_client_socket);

        cout << "Tracker said: " << response;

        if (response.find("Stopped sharing") != string::npos) {
            // 1. Remove from filedetails map to stop seeding it
            if (filedetails.count(filename)) {
                delete filedetails[filename];
                filedetails.erase(filename);
            }

            // 2. Remove from sharedFiles vector to prevent re-sharing on session restore
            int group_id = stoi(group_id_str);
            sharedFiles.erase(
                std::remove_if(sharedFiles.begin(), sharedFiles.end(),
                    [&](const pair<string, int>& file) {
                        string path = file.first;
                        size_t pos = path.find_last_of("/\\");
                        string name_from_path = (pos == std::string::npos) ? path : path.substr(pos + 1);
                        
                        return name_from_path == filename && file.second == group_id;
                    }),
                sharedFiles.end()
            );
            cout << "Client state updated. You are no longer sharing " << filename << endl;
        }
        return;
    }
    // END: ADDED stop_share IMPLEMENTATION

    const int MAX_RETRIES = 3;
    for (int retry = 0; retry < MAX_RETRIES; ++retry) {
        if (g_client_socket < 0) {
            cout << "Not connected. Attempting to connect..." << endl;
            if (connectToTracker(g_client_socket) < 0) { cout << "Reconnection failed: All trackers unavailable." << endl; return; }
            restoreSessionState(g_client_socket);
        }

        string full_command = line + "\n";
        
        if (command == "upload_file") {
            if (inputs.size() < 3) { cout << "Usage: upload_file <filepath> <group_id>" << endl; return; }
            string filepath = inputs[1];
            int groupid = stoi(inputs[2]);
            
            ifstream file(filepath, ifstream::binary);
            if (!file) { cout << "Error: Cannot open file " << filepath << endl; return; }

            string full_file_content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            string complete_hash = hashfunc(full_file_content.c_str(), full_file_content.length(), true);
            file.clear();
            file.seekg(0);

            char buffer[PIECE_SIZE];
            string concatenated_hashes = "";
            while(file.read(buffer, PIECE_SIZE) || file.gcount() > 0) {
                concatenated_hashes += hashfunc(buffer, file.gcount());
            }
            file.close();

            vector<char*> fileparse = split1(filepath.c_str(), "/");
            string filename = string(fileparse.back());
            
            full_command = "upload_file " + filename + " " + to_string(groupid) + " " + concatenated_hashes + " " + complete_hash + "\n";
        }

        if (send(g_client_socket, full_command.c_str(), full_command.size(), 0) < 0) {
            perror("Send failed"); close(g_client_socket); g_client_socket = -1;
            cout << "Connection lost. Will retry..." << endl; continue;
        }

        string response = receiveResponse(g_client_socket);
        if (response.empty()) {
            cout << "Receive failed. Connection likely closed by tracker." << endl;
            close(g_client_socket); g_client_socket = -1;
            cout << "Connection lost. Will retry..." << endl; continue;
        }

        cout << "Tracker said: " << response;

        if (command == "login" && response.find("Welcome") != string::npos) {
            currentUser = string(inputs[1]); currentPassword = string(inputs[2]); isLoggedIn = true;
            string portCmd = "port " + to_string(globalStoreClientPort);
            send(g_client_socket, (portCmd + "\n").c_str(), portCmd.size() + 1, 0);
            cout << "Listening Port value sent to tracker." << endl;
        } else if (command == "logout") {
            isLoggedIn = false; currentUser = ""; currentPassword = "";
            sharedFiles.clear(); filedetails.clear(); close(g_client_socket); g_client_socket = -1;
        } else if (command == "upload_file" && response.find("file uploaded") != string::npos) {
            string filepath = inputs[1]; int groupid = stoi(inputs[2]);
            sharedFiles.emplace_back(filepath, groupid);
            int size = getFileSize(filepath);
            int numberOfPieces = (size + PIECE_SIZE - 1) / PIECE_SIZE;
            vector<char*> fileparse = split1(filepath.c_str(), "/");
            string filename = string(fileparse.back());
            FileData *f = new FileData(size, groupid, numberOfPieces, filepath, filename);
            f->set_as_seeder();
            filedetails[filename] = f;
        }
        return; 
    }
    cout << "Command failed after multiple retries. Please check network and tracker status." << endl;
}


int main(int argc, char const *argv[]){
    if(argc != 3){
        cout << "Usage: ./client <IP>:<PORT> <tracker_info_file>" << endl;
        exit(EXIT_FAILURE);
    }

    string temp = argv[1];
    string ipClient, portStr;
    parseInput(temp, ipClient, portStr);
    globalStoreClientPort = stoi(portStr);

    ifstream file(argv[2]);
    string line;
    while (getline(file, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != string::npos) {
            g_trackers.emplace_back(line.substr(0, colonPos), stoi(line.substr(colonPos + 1)));
        }
    }
    file.close();

    if (connectToTracker(g_client_socket) < 0) {
        cout << "Initial connection failed: All trackers unavailable." << endl;
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in address1;
    int my_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(my_server_socket == 0) { exit(EXIT_FAILURE); }

    address1.sin_family = AF_INET;
    address1.sin_addr.s_addr = INADDR_ANY;
    address1.sin_port = htons(globalStoreClientPort);

    if(bind(my_server_socket, (struct sockaddr*)&address1, sizeof(address1)) < 0){
        perror("Bind failure");
        exit(EXIT_FAILURE);
    }

    thread listenthread(listeningthread, my_server_socket, address1);
    
    vector<thread> workers;
    for (int i = 0; i < NO_OF_THREADS; ++i) {
        workers.emplace_back(workerThread);
    }
    
    while(true){
        string ip;
        cout << "> ";
        getline(cin, ip);
        if (cin.eof() || ip == "quit") break;
        if(ip.empty()) continue;
        handleCommand(ip);
    }
    
    done = true;
    conditionfortaskQueue.notify_all();
    for(auto& worker : workers) if(worker.joinable()) worker.join();
    if(listenthread.joinable()) listenthread.join();
    if(g_client_socket > 0) close(g_client_socket);

    return 0;
}