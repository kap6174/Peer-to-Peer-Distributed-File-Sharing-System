# 🧩 PeerShare – Distributed Peer-to-Peer File Sharing System

PeerShare is a distributed, multi-tracker peer-to-peer (P2P) file sharing system inspired by BitTorrent.

It allows users to create groups, share files, and download them in parallel from multiple peers. The system supports tracker synchronization, multi-threaded concurrent downloads, and SHA-1–based file integrity verification, all implemented entirely using system calls and sockets in C++.

---

## ⚙️ Features

### 🔐 User & Group Management
- **User Registration/Login:** Each user registers and authenticates with the tracker before performing any operations.  
- **Group Creation & Membership:** Users can create groups, send join requests, and leave groups.  
- **Request Handling:** Group owners can view, accept, or reject pending join requests.  

### 📁 File Sharing & Downloading
- **Upload Files:** Users can share files within a group. The tracker stores file metadata, SHA-1 hashes, and seeder information.  
- **Parallel Downloads:** Implements a custom piece selection algorithm to download file chunks concurrently from multiple peers.  
- **Piece Verification:** Each downloaded chunk is verified using SHA-1 to ensure data integrity before reconstruction.  
- **Partial Seeding:** As soon as a file piece is downloaded, it becomes shareable to other peers (“leecher mode”).  
- **Stop Sharing:** A user can stop sharing a file or all files on logout.  

### 🌐 Tracker Synchronization
- **Multi-Tracker Architecture:** Supports two synchronized trackers — ensuring availability and redundancy even if one tracker goes down.  
- **State Replication:** Any updates (file uploads, group changes, seeding info) are mirrored across trackers to maintain consistency.  

### 🧵 Concurrency and Networking
- **Multi-threaded Server:** Trackers handle multiple concurrent client requests using threads.  
- **Non-blocking Socket Communication:** TCP-based communication ensures reliable data transfer between clients and trackers.  
- **Atomic Operations:** Protects shared data structures and ensures correctness in concurrent environments.  

---

## 🧱 Architecture Overview

### 1. Tracker
- Acts as a metadata coordinator for the network.  
- Maintains mappings of `users → groups → files → peers`.  
- Handles synchronization with other tracker(s).  
- Processes commands such as: `create_user`, `login`, `create_group`, `join_group`, `list_files`, `upload_file`, `download_file`, `stop_share`, `logout`.  

### 2. Client
- Acts as both peer and server — can download from others while serving uploaded file pieces.  
- Communicates with tracker for group/file info, and directly with peers for data transfer.  
- Implements custom piecewise download and verification logic.  

---

## 🧩 Commands Overview

| Command | Description |
|---------|------------|
| `create_user <user_id> <passwd>` | Registers a new user |
| `login <user_id> <passwd>` | Logs in an existing user |
| `create_group <group_id>` | Creates a new group |
| `join_group <group_id>` | Sends join request |
| `leave_group <group_id>` | Leaves an existing group |
| `list_requests <group_id>` | Lists pending join requests (owner only) |
| `accept_request <group_id> <user_id>` | Accepts a user’s join request |
| `list_groups` | Lists all available groups |
| `list_files <group_id>` | Lists files shared in a group |
| `upload_file <file_path> <group_id>` | Shares file with the group |
| `download_file <group_id> <filename> <destination_path>` | Downloads file in parallel from multiple peers |
| `show_downloads` | Displays ongoing and completed downloads |
| `stop_share <group_id> <filename>` | Stops sharing a file |
| `logout` | Logs out and stops sharing all files |

---

## 🔧 Implementation Details
- **Language:** C++
- **Networking:** TCP sockets  
- **Concurrency:** POSIX threads (`pthread`)  
- **Hashing:** OpenSSL SHA-1 for file and chunk integrity  
- **Piece Size:** 512 KB  
- **Tracker Synchronization:** Socket-based update propagation between trackers  

---

## 🗂️ Project Structure

```
PeerShare/
│
├── tracker/
│   ├── tracker.cpp
│   ├── header.h
│   ├── makefile
│   └── tracker_info.txt
│
├── client/
│   ├── client.cpp
│   ├── selectionAlgo.cpp
│   ├── splitting.cpp
│   ├── fileSize.cpp
│   ├── readInputFile.cpp
│   ├── header.h
│   └── makefile
│
└── README.md
```

---

## 🚀 How to Compile and Run

### Tracker
```bash
cd tracker
make
./tracker tracker_info.txt 1     # Run first tracker
./tracker tracker_info.txt 2     # Run second tracker
```

### Client
```bash
cd client
make
./client <IP>:<PORT> tracker_info.txt
```
Run multiple clients in separate terminals.

---

## 🧠 Concepts Demonstrated
- Multi-threading and concurrency control  
- Network socket programming  
- Tracker synchronization and fault tolerance  
- Piece selection and verification algorithms  
- SHA-1–based integrity checking  

---

## 📜 Future Enhancements
- Encrypted peer communication (TLS)  
- Dynamic tracker discovery  
- Fault-tolerant peer recovery  
- Enhanced UI/CLI with progress visualization
