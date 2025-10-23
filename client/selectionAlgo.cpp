#include <iostream>
#include <unordered_map>
#include <vector>
#include "header.h"
#include <climits>

using namespace std;

// will follow rarest piece first 
unordered_map<int, int> pieceSelectionAlgorithm(unordered_map<int, string> clientPieceMap) {
    unordered_map<int, int> pieceFrequency;
    unordered_map<int, int> pieceToClientMap;

    int pieceCount = clientPieceMap.begin()->second.size();
    for (const auto& client : clientPieceMap) {
        const std::string& pieceMatrix = client.second;
        for (int i = 0; i < pieceCount; ++i) {
            if (pieceMatrix[i] == '1') {
                pieceFrequency[i]++;
            }
        }
    }

    std::vector<bool> assignedPieces(pieceCount, false);

    for (int i = 0; i < pieceCount; ++i) {
        int rarestPiece = -1;
        int rarestFrequency = INT_MAX;

        for (const auto& freq : pieceFrequency) {
            int pieceIndex = freq.first;
            int frequency = freq.second;

            if (!assignedPieces[pieceIndex] && frequency < rarestFrequency) {
                rarestPiece = pieceIndex;
                rarestFrequency = frequency;
            }
        }

        if (rarestPiece != -1) {
            for (const auto& client : clientPieceMap) {
                int clientPort = client.first;
                const std::string& pieceMatrix = client.second;

                if (pieceMatrix[rarestPiece] == '1') {
                    pieceToClientMap[rarestPiece] = clientPort;
                    assignedPieces[rarestPiece] = true;
                    break;
                }
            }
        }
    }

    return pieceToClientMap;
}