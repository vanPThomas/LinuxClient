#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>

void handleSystemCallError(std::string errorMsg);
void receiveMessages(int bytesRead, int clientSocket, char buffer[1024], int bufferSize);
void sendMessage(int clientSocket, char outMessage[1024], int bufferSize, const std::string &username);

int main()
{
    const int bufferSize = 1024;
    char buffer[bufferSize];
    char outMessage[bufferSize];

    std::cout << "Enter server IP: ";
    std::string serverIP;
    std::cin >> serverIP;

    std::cout << "Enter server port: ";
    int serverPort;
    std::cin >> serverPort;

    std::cout << "Enter your username: ";
    std::string username;
    std::cin >> username;

    // create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        handleSystemCallError("Failed to create socket");
    }

    // Set up the server address structure
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);

    // check IP validity by converting it to binary
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr) <= 0)
    {
        handleSystemCallError("Invalid address or address not supported\n");
        close(clientSocket);
        return -1;
    }

    // connect to server
    if (connect(clientSocket, reinterpret_cast<struct sockaddr *>(&serverAddress), sizeof(serverAddress)) == -1)
    {
        handleSystemCallError("Error when connecting to server\n");
        close(clientSocket);
        return -1;
    }

    const char *messageToSend = "Hello From Client!\n";
    send(clientSocket, messageToSend, strlen(messageToSend), 0);
    std::cout << "Message sent to server: " << messageToSend << "\n";

    // Receive and print message from server
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        std::cout << buffer << "\n";
    }
    else
    {
        std::cerr << "Error receiving message\n";
    }

    std::thread first(receiveMessages, bytesRead, clientSocket, buffer, bufferSize);
    std::thread second(sendMessage, clientSocket, outMessage, bufferSize, username);

    first.join();
    second.join();

    close(clientSocket);
}

void handleSystemCallError(std::string errorMsg)
{
    std::cout << errorMsg << ", errno: " << errno << "\n";
    exit(EXIT_FAILURE);
}

void receiveMessages(int bytesRead, int clientSocket, char buffer[1024], int bufferSize)
{
    while (true)
    {
        bytesRead = recv(clientSocket, buffer, bufferSize, 0);
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            std::cout << "Message received: " << buffer << "\n";
        }
    }
}

void sendMessage(int clientSocket, char outMessage[1024], int bufferSize, const std::string &username)
{
    while (true)
    {
        std::string userMessage;
        std::getline(std::cin, userMessage);

        if (!userMessage.empty())
        {
            userMessage = username + ": " + userMessage;

            send(clientSocket, userMessage.c_str(), userMessage.length(), 0);
        }
    }
}
