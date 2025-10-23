#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <locale>
#include "header.h"
#include <chrono>
#include <sstream>
#include <fstream>

#define BUFFER_SIZE 8192 // Increased buffer for larger commands with hashes
using namespace std;

atomic<bool> running(true);

// --- Data Structures ---
unordered_map<string, string> map_user;
unordered_map<string, bool> loggedin;
unordered_map<string, int> socketInfo;
unordered_map<int, string> loggedUser;
unordered_map<int, vector<string>> groupMembers;
unordered_map<int, string> groupOwner;
unordered_map<int, vector<string>> requests;
unordered_map<string, int> listeningPort;
unordered_map<int, vector<string>> filesingroup;
unordered_map<string, vector<string>> fileswithclient;
unordered_map<string, int> fileToGroup;
unordered_map<string, string> piecewiseFileHashes; // Renamed for clarity
// --- NEW FEATURE: Map for complete file hashes ---
unordered_map<string, string> completeFileHashes;


vector<string> split(const string& s, const string& delimiter) {
    vector<string> tokens;
    string temp_s = s;
    size_t pos = 0;
    string token;
    while ((pos = temp_s.find(delimiter)) != string::npos) {
        token = temp_s.substr(0, pos);
        tokens.push_back(token);
        temp_s.erase(0, pos + delimiter.length());
    }
    tokens.push_back(temp_s);
    return tokens;
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

string serializeMetadata() {
    stringstream ss;
    ss << "map_user:";
    for (const auto& entry : map_user) { ss << entry.first << "=" << entry.second << ";"; }
    ss << "|loggedin:";
    for (const auto& entry : loggedin) { ss << entry.first << "=" << (entry.second ? "true" : "false") << ";"; }
    ss << "|groupMembers:";
    for (const auto& entry : groupMembers) {
        ss << entry.first << "=[";
        for (size_t i = 0; i < entry.second.size(); ++i) { ss << entry.second[i] << (i < entry.second.size() - 1 ? "," : ""); }
        ss << "];";
    }
    ss << "|groupOwner:";
    for (const auto& entry : groupOwner) { ss << entry.first << "=" << entry.second << ";"; }
    ss << "|requests:";
    for (const auto& entry : requests) {
        ss << entry.first << "=[";
        for (size_t i = 0; i < entry.second.size(); ++i) { ss << entry.second[i] << (i < entry.second.size() - 1 ? "," : ""); }
        ss << "];";
    }
    ss << "|filesingroup:";
    for (const auto& entry : filesingroup) {
        ss << entry.first << "=[";
        for (size_t i = 0; i < entry.second.size(); ++i) { ss << entry.second[i] << (i < entry.second.size() - 1 ? "," : ""); }
        ss << "];";
    }
    ss << "|fileswithclient:";
    for (const auto& entry : fileswithclient) {
        ss << entry.first << "=[";
        for (size_t i = 0; i < entry.second.size(); ++i) { ss << entry.second[i] << (i < entry.second.size() - 1 ? "," : ""); }
        ss << "];";
    }
    ss << "|listeningPort:";
    for (const auto& entry : listeningPort) { ss << entry.first << "=" << entry.second << ";"; }
    ss << "|fileToGroup:";
    for (const auto& entry : fileToGroup) { ss << entry.first << "=" << entry.second << ";"; }
    ss << "|piecewiseFileHashes:";
    for (const auto& entry : piecewiseFileHashes) { ss << entry.first << "=" << entry.second << ";"; }
    // --- NEW FEATURE: Serialize complete file hashes ---
    ss << "|completeFileHashes:";
    for (const auto& entry : completeFileHashes) { ss << entry.first << "=" << entry.second << ";"; }
    return ss.str();
}

void deserializeMetadata(const string& data) {
    stringstream ss(data);
    string section;
    while (getline(ss, section, '|')) {
        if (section.empty()) continue;
        size_t colonPos = section.find(':');
        if (colonPos == string::npos) continue;
        string key = section.substr(0, colonPos);
        string values = section.substr(colonPos + 1);

        if (key == "map_user" || key == "piecewiseFileHashes" || key == "completeFileHashes") {
            auto* targetMap = (key == "map_user") ? &map_user 
                          : (key == "piecewiseFileHashes") ? &piecewiseFileHashes 
                          : &completeFileHashes;
            stringstream vss(values); string pair;
            while (getline(vss, pair, ';')) {
                if (pair.empty()) continue;
                size_t eqPos = pair.find('=');
                if (eqPos != string::npos) {
                    (*targetMap)[pair.substr(0, eqPos)] = pair.substr(eqPos + 1);
                }
            }
        } else if (key == "loggedin") {
            stringstream vss(values); string pair;
            while (getline(vss, pair, ';')) {
                if (pair.empty()) continue;
                size_t eqPos = pair.find('=');
                if (eqPos != string::npos) loggedin[pair.substr(0, eqPos)] = (pair.substr(eqPos + 1) == "true");
            }
        } else if (key == "groupMembers" || key == "requests" || key == "filesingroup") {
            auto* targetMap = (key == "groupMembers") ? &groupMembers : (key == "requests") ? &requests : &filesingroup;
            stringstream vss(values); string pair;
            while (getline(vss, pair, ';')) {
                if (pair.empty()) continue;
                size_t bracketPos = pair.find('['); if (bracketPos == string::npos) continue;
                string keyStr = pair.substr(0, bracketPos);
                if (keyStr.empty()) continue;
                int id = stoi(keyStr);
                size_t closeBracket = pair.find(']'); if (closeBracket == string::npos) continue;
                string listStr = pair.substr(bracketPos + 1, closeBracket - bracketPos - 1);
                stringstream lss(listStr); string item;
                while (getline(lss, item, ',')) {
                    if (!item.empty()) {
                        string trimmed_item = trim(item);
                        if (find((*targetMap)[id].begin(), (*targetMap)[id].end(), trimmed_item) == (*targetMap)[id].end()) {
                            (*targetMap)[id].push_back(trimmed_item);
                        }
                    }
                }
            }
        } else if (key == "groupOwner") {
            stringstream vss(values); string pair;
            while (getline(vss, pair, ';')) {
                if (pair.empty()) continue;
                size_t eqPos = pair.find('=');
                if (eqPos != string::npos) {
                     string keyStr = pair.substr(0, eqPos);
                     if (keyStr.empty()) continue;
                     groupOwner[stoi(keyStr)] = pair.substr(eqPos + 1);
                }
            }
        } else if (key == "fileswithclient") {
             stringstream vss(values); string pair;
            while (getline(vss, pair, ';')) {
                if (pair.empty()) continue;
                size_t bracketPos = pair.find('['); if (bracketPos == string::npos) continue;
                string fname = pair.substr(0, bracketPos);
                if (fname.empty()) continue;
                size_t closeBracket = pair.find(']'); if (closeBracket == string::npos) continue;
                string listStr = pair.substr(bracketPos + 1, closeBracket - bracketPos - 1);
                stringstream lss(listStr); string item;
                while (getline(lss, item, ',')) {
                    if (!item.empty()) {
                        string trimmed_item = trim(item);
                         if (find(fileswithclient[fname].begin(), fileswithclient[fname].end(), trimmed_item) == fileswithclient[fname].end()) {
                            fileswithclient[fname].push_back(trimmed_item);
                        }
                    }
                }
            }
        } else if (key == "listeningPort" || key == "fileToGroup") {
             stringstream vss(values); string pair;
             while(getline(vss, pair, ';')) {
                 if(pair.empty()) continue;
                 size_t eqPos = pair.find('=');
                 if(eqPos != string::npos) {
                     string map_key = pair.substr(0, eqPos);
                     string val_str = pair.substr(eqPos + 1);
                     if (map_key.empty() || val_str.empty()) continue;
                     int map_val = stoi(val_str);
                     if(key == "listeningPort") listeningPort[map_key] = map_val;
                     else fileToGroup[map_key] = map_val;
                 }
             }
        }
    }
}

void processSyncMessage(const string& msg) {
    if (msg.rfind("sync:", 0) == 0) {
        string metadata = msg.substr(5);
        deserializeMetadata(metadata);
        cout << "Processed sync data." << endl;
    }
}

void sendMetadataToTracker(const string& trackerIp, int trackerPort, const string& metadata) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(trackerPort);
    inet_pton(AF_INET, trackerIp.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return;
    }
    string syncMsg = "sync:" + metadata;
    send(sock, syncMsg.c_str(), syncMsg.size(), 0);
    close(sock);
}

void requestInitialSync(const vector<pair<string, int>>& otherTrackers) {
    for (const auto& tracker : otherTrackers) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(tracker.second);
        inet_pton(AF_INET, tracker.first.c_str(), &addr.sin_addr);
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) >= 0) {
            string syncReq = "sync_request\n";
            send(sock, syncReq.c_str(), syncReq.size(), 0);
            char buffer[BUFFER_SIZE * 10] = {0};
            int bytes = read(sock, buffer, sizeof(buffer));
            if (bytes > 0) {
                string msg = string(buffer, bytes);
                processSyncMessage(msg);
            }
            close(sock);
        }
    }
}

void handleClient(int client_socket) {
    char message_buffer[BUFFER_SIZE * 10] = {0};

    while (true) {
        memset(message_buffer, 0, sizeof(message_buffer));
        int bytes_reading = read(client_socket, message_buffer, sizeof(message_buffer) - 1);

        if (bytes_reading <= 0) {
            if (loggedUser.count(client_socket)) {
                string username = loggedUser[client_socket];
                cout << "Client " << username << " disconnected" << endl;
                listeningPort.erase(username);
                vector<string> files_to_prune;
                for (auto& pair : fileswithclient) {
                    string filename = pair.first;
                    vector<string>& clients = pair.second;
                    clients.erase(remove(clients.begin(), clients.end(), username), clients.end());
                    if (clients.empty()) files_to_prune.push_back(filename);
                }
                for (const auto& filename : files_to_prune) {
                    if (fileToGroup.count(filename)) {
                        int groupid = fileToGroup[filename];
                        auto& files_in_grp = filesingroup[groupid];
                        files_in_grp.erase(remove(files_in_grp.begin(), files_in_grp.end(), filename), files_in_grp.end());
                        fileToGroup.erase(filename);
                        piecewiseFileHashes.erase(filename);
                        completeFileHashes.erase(filename);
                    }
                    fileswithclient.erase(filename);
                }
                loggedUser.erase(client_socket);
                loggedin[username] = false;
                socketInfo.erase(username);
            } else {
                cout << "Unauthenticated client or peer disconnected" << endl;
            }
            close(client_socket);
            return;
        }

        string full_message(message_buffer, bytes_reading);
        cout << "Received Message: " << full_message;
        fflush(stdout);

        string msg = trim(full_message);

        if (msg.rfind("sync:", 0) == 0) {
            processSyncMessage(msg);
            continue; 
        } else if (msg == "sync_request") {
            string metadata = serializeMetadata();
            string syncMsg = "sync:" + metadata;
            send(client_socket, syncMsg.c_str(), syncMsg.size(), 0);
            close(client_socket);
            return;
        }

        vector<string> vec = split(msg, " ");
        if (vec.empty()) continue;
        
        string command = vec[0];
        
        if (command == "upload_file") {
            if (vec.size() < 5) { send(client_socket, "Error: Upload command requires filename, group_id, piecewise hash, and complete hash.\n", 80, 0); continue; }
            string filename = vec[1];
            int groupid = stoi(vec[2]);
            string piecewise_hash = vec[3];
            string complete_hash = vec[4];

            if (loggedUser.count(client_socket)) {
                string user = loggedUser[client_socket];
                auto& files = filesingroup[groupid];
                if (find(files.begin(), files.end(), filename) == files.end()) files.push_back(filename);
                
                auto& sharers = fileswithclient[filename];
                if (find(sharers.begin(), sharers.end(), user) == sharers.end()) sharers.push_back(user);

                fileToGroup[filename] = groupid;
                piecewiseFileHashes[filename] = piecewise_hash;
                completeFileHashes[filename] = complete_hash;

                send(client_socket, "file uploaded\n", 14, 0);
            } else {
                 send(client_socket, "Error: Not logged in\n", 22, 0);
            }
        } else if (command == "download_file") {
            if (vec.size() < 3) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupid = stoi(vec[1]);
            string filename = vec[2];
            string response = "";

            bool found = filesingroup.count(groupid) && find(filesingroup[groupid].begin(), filesingroup[groupid].end(), filename) != filesingroup[groupid].end();

            if (!found || !piecewiseFileHashes.count(filename)) {
                response = "file not in group or hash not found\n";
            } else {
                for (const auto& user : fileswithclient[filename]) {
                    if (listeningPort.count(user)) {
                        response += to_string(listeningPort[user]) + " ";
                    }
                }
                response += "|"; // Separator
                response += piecewiseFileHashes[filename]; // Piecewise hashes
                response += "|"; // Separator
                response += completeFileHashes[filename]; // Complete hash
                response += "\n";

                if(loggedUser.count(client_socket)) {
                    string user = loggedUser[client_socket];
                    auto& sharers = fileswithclient[filename];
                    if (find(sharers.begin(), sharers.end(), user) == sharers.end()) {
                        sharers.push_back(user);
                    }
                }
            }
            send(client_socket, response.c_str(), response.size(), 0);
        } else if (command == "stop_share") {
             if (vec.size() < 3) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            string filename = vec[1];
            int groupid = stoi(vec[2]);
            if (loggedUser.count(client_socket)) {
                string user = loggedUser[client_socket];
                auto& clients = fileswithclient[filename];
                clients.erase(remove(clients.begin(), clients.end(), user), clients.end());
                if (clients.empty()) {
                    auto& files = filesingroup[groupid];
                    files.erase(remove(files.begin(), files.end(), filename), files.end());
                    fileToGroup.erase(filename);
                    piecewiseFileHashes.erase(filename);
                    completeFileHashes.erase(filename);
                }
            }
            send(client_socket, "Stopped sharing\n", 16, 0);
        } else if (command == "create_user") {
            if (vec.size() < 3) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            string username = vec[1];
            string password = vec[2];
            const char* response = (map_user.find(username) == map_user.end()) ? "New user created\n" : "User exists\n";
            if (strcmp(response, "New user created\n") == 0) map_user[username] = password;
            send(client_socket, response, strlen(response), 0);
        } else if (command == "login") {
            if (vec.size() < 3) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            string username = vec[1];
            string password = vec[2];
            const char* response;
            if (map_user.count(username)) {
                if (map_user[username] == password) {
                    response = "Welcome back\n";
                    loggedin[username] = true;
                    loggedUser[client_socket] = username;
                    socketInfo[username] = client_socket;
                } else {
                    response = "Wrong Password!\n";
                }
            } else {
                response = "Account not Found!\n";
            }
            send(client_socket, response, strlen(response), 0);
        } else if (command == "list_files") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupid = stoi(vec[1]);
            string str = "";
            if (filesingroup.count(groupid)) {
                for (const auto& it : filesingroup[groupid]) {
                    str += it + "\n";
                }
            }
            if (str.empty()) {
                str = "\n";
            }
            send(client_socket, str.c_str(), str.size(), 0);
        } else if (command == "create_group") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupId = stoi(vec[1]);
            string response;
            if (!loggedUser.count(client_socket)) {
                response = "User is Invalid\n";
            } else if (groupOwner.count(groupId)) {
                response = "Group Already exists\n";
            } else {
                string owner = loggedUser[client_socket];
                groupOwner[groupId] = owner;
                groupMembers[groupId].push_back(owner);
                response = "Group Created. You are now an Admin\n";
            }
            send(client_socket, response.c_str(), response.size(), 0);
        } else if (command == "join_group") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupId = stoi(vec[1]);
            string response;
            if (!loggedUser.count(client_socket)) {
                response = "User is Invalid\n";
            } else if (!groupOwner.count(groupId)) {
                response = "Cannot access group\n";
            } else {
                requests[groupId].push_back(loggedUser[client_socket]);
                response = "Request sent to Owner\n";
            }
            send(client_socket, response.c_str(), response.size(), 0);
        } else if (command == "accept_request") {
            if (vec.size() < 3) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupId = stoi(vec[1]);
            string user = vec[2];
            string response;
            if (groupOwner.count(groupId) && loggedUser.count(client_socket) && groupOwner[groupId] == loggedUser[client_socket]) {
                groupMembers[groupId].push_back(user);
                requests[groupId].erase(remove(requests[groupId].begin(), requests[groupId].end(), user), requests[groupId].end());
                response = "accepted " + to_string(groupId) + "\n";
            } else {
                response = "You are not the owner of " + to_string(groupId) + "\n";
            }
            send(client_socket, response.c_str(), response.size(), 0);
        } else if (command == "list_requests") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupId = stoi(vec[1]);
            string str = "";
            if(requests.count(groupId)) {
                for (const auto& it : requests[groupId]) str += it + " ";
            }
            str = trim(str) + "\n";
            send(client_socket, str.c_str(), str.size(), 0);
        } else if (command == "list_groups") {
            string str = "";
            for (const auto& it : groupOwner) str += to_string(it.first) + " ";
            str = trim(str) + "\n";
            send(client_socket, str.c_str(), str.size(), 0);
        } else if (command == "leave_group") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int groupId = stoi(vec[1]);
            string response;
            if (!loggedUser.count(client_socket)) {
                response = "User is invalid\n";
            } else {
                string user = loggedUser[client_socket];
                auto& members = groupMembers[groupId];
                auto it = find(members.begin(), members.end(), user);
                if (it != members.end()) {
                    members.erase(it);
                    if (groupOwner[groupId] == user) {
                        if (members.empty()) {
                            groupMembers.erase(groupId);
                            groupOwner.erase(groupId);
                        } else {
                            groupOwner[groupId] = members[0];
                        }
                    }
                    response = "You have been removed\n";
                } else {
                    response = "You are not in the group!\n";
                }
            }
            send(client_socket, response.c_str(), response.size(), 0);
        } else if (command == "logout") {
            send(client_socket, "Logged out successfully\n", 24, 0);
            close(client_socket);
            return;
        } else if (command == "port") {
            if (vec.size() < 2) { send(client_socket, "Error: Invalid arguments\n", 25, 0); continue; }
            int listeningP = stoi(vec[1]);
            if (loggedUser.count(client_socket)) {
                listeningPort[loggedUser[client_socket]] = listeningP;
                cout << "\nListening Port " << listeningP << " for user " << loggedUser[client_socket] << " saved." << endl;
            }
        } else {
             send(client_socket, "command not recognized\n", 24, 0);
        }
    }
}

void quitCommand() {
    string input;
    while (running) {
        cin >> input;
        if (input == "quit") {
            running = false;
            cout << "Tracker quitting..." << endl;
            break;
        }
    }
}

vector<pair<string, int>> loadAllTrackers(const string& file_path) {
    vector<pair<string, int>> trackers;
    ifstream file(file_path);
    string line;
    while (getline(file, line)) {
        size_t colonPos = line.find(':');
        if (colonPos != string::npos) {
            trackers.emplace_back(line.substr(0, colonPos), stoi(line.substr(colonPos + 1)));
        }
    }
    return trackers;
}

void syncThread(vector<pair<string, int>> otherTrackers, int myPort) {
    while (running) {
        this_thread::sleep_for(chrono::seconds(5));
        if (!running) break;
        string metadata = serializeMetadata();
        for (const auto& tracker : otherTrackers) {
             if (tracker.second != myPort) {
                sendMetadataToTracker(tracker.first, tracker.second, metadata);
            }
        }
    }
}

int main(int argc, char const* argv[]) {
    if (argc != 3) {
        cout << "Usage: ./tracker <tracker_info_file> <tracker_number>" << endl;
        return 0;
    }

    string file_path = argv[1];
    int trackerNo = stoi(argv[2]);
    string trackerIp, trackerPort;
    parseFile(file_path, trackerNo, trackerIp, trackerPort);
    int trackerPortInt = stoi(trackerPort);
    vector<pair<string, int>> allTrackers = loadAllTrackers(file_path);
    vector<pair<string, int>> otherTrackers;
    for (const auto& t : allTrackers) {
        if (t.second != trackerPortInt) {
            otherTrackers.push_back(t);
        }
    }

    requestInitialSync(otherTrackers);
    thread sync_thread(syncThread, otherTrackers, trackerPortInt);

    int server_socket;
    struct sockaddr_in address;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == 0) {
        perror("Socket creation failed"); exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(trackerPortInt);
    if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failure"); close(server_socket); exit(EXIT_FAILURE);
    }
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed"); close(server_socket); exit(EXIT_FAILURE);
    }
    cout << "Tracker listening on port " << trackerPortInt << endl;
    thread quit_thread(quitCommand);

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_socket, &readfds);
        struct timeval timeout = {1, 0};
        if (select(server_socket + 1, &readfds, NULL, NULL, &timeout) > 0) {
            if (FD_ISSET(server_socket, &readfds)) {
                int client_socket = accept(server_socket, NULL, NULL);
                if (client_socket < 0) {
                    perror("Accept failed"); continue;
                }
                thread(handleClient, client_socket).detach();
            }
        }
    }

    running = false;
    if(sync_thread.joinable()) sync_thread.join();
    if(quit_thread.joinable()) quit_thread.join();
    close(server_socket);
    return 0;
}