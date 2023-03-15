#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()
#include <fcntl.h>
#include <netinet/in.h> // struct sockaddr_in
#include <ctype.h>

#define BUFFER_SIZE 71680

/**
 * Decrypt Client Code
 * 1. Create a socket
 * 2. Connect to server
 * 3. Send data to server
 * 4. Receive data from server
 * 5. Close socket
 */

// Error function used for reporting issues
void error(const char *msg)
{
    perror(msg);
    exit(0);
}

// Set up the address struct
void setupAddressStruct(struct sockaddr_in *address, int portNumber)
{

    // Clear out the address struct
    memset((char *)address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);

    // Get the DNS entry for this host name
    struct hostent *hostInfo = gethostbyname("localhost");
    if (hostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR, no such host \n");
        exit(0);
    }
    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char *)&address->sin_addr.s_addr,
           hostInfo->h_addr_list[0],
           hostInfo->h_length);
}

/*
 * This function was created using beej's guide to network programming
 * 7.4 Handling Partial send()s section. 
 * https://beej.us/guide/bgnet/html/#sendrecv
*/
int sendall(int s, char *buf, int len)
{
    int total = 0;        // how many bytes we've sent
    int bytesleft = len; // how many we have left to send
    int n;

    while(total < len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    } 

    len = total; // return number actually sent here

    return n==-1?-1:0; // return -1 on failure, 0 on success
} 

/*
 * This function was created using beej's guide to network programming
 * 7.4 Handling Partial recv()s section. 
 * https://beej.us/guide/bgnet/html/#sendrecv
*/
int recvall(int s, char *buf, int len) {
    int total = 0;         // how many bytes we've received so far
    int bytesleft = len;   // how many bytes we have left to receive
    int n;
    // printf("Client-recv: len: %d , bytesleft: %d \n", len, bytesleft);
    while (total < len) {
        n = recv(s, buf + total, bytesleft, 0);
        if (n == -1) { break; }
        if (n == 0) { return total; } // connection closed by remote host
        total += n;
        bytesleft -= n;
    }

    if (n == -1) {
        // an error occurred while receiving
        return -1;
    } else {
        // successfully received all data
        return total;
    }
}

int main(int argc, char *argv[])
{
    int socketFD, portNumber, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];
    memset(buffer, '\0', sizeof(buffer));
    FILE *fd;
    int nBytes;
    int authSend, authRead;
    char auth[2] = "d";

    // Check user input for correct number of arguments
    if (argc < 4)
    {
        fprintf(stderr, "USAGE: %s plaintext key port \n", argv[0]);
        exit(0);
    }

    // Create a socket to connect to server
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
    {
        error("CLIENT: ERROR opening socket");
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]));

    // Connect to server
    if (connect(socketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        error("CLIENT: ERROR connecting");
    }

    // Get the Key and Text files from user input
    int key = open(argv[2], O_RDONLY);
    int keySize = lseek(key, 0, SEEK_END);
    int text = open(argv[1], O_RDONLY);
    int textSize = lseek(text, 0, SEEK_END);

    if (text == -1 || key == -1)
    {
        fprintf(stderr, "CLIENT: ERROR - could not open file \n");
        exit(1);
    }

    // Check if key is long enough. Print error message and exit if not
    if (keySize < textSize)
    {
        fprintf(stderr, "CLIENT: Error - key '%s' is too short \n", argv[2]);
        exit(1);
    }

    // If the text file is empty, send an empty string to the server
    if (textSize > 0)
    {
        // Read text file and check for invalid characters
        while (read(text, buffer, 1) != 0)
        {
            // Start reading at the beginning of the file
            lseek(text, 0, SEEK_SET);
            if (!(isspace(buffer[0]) || isalpha(buffer[0])))
            {
                fprintf(stderr, "ERROR: found invalid character in %s \n", argv[1]);
                exit(1);
            }
        }
    }

    // Authenticate client as dec_client
    authSend = sendall(socketFD, auth, sizeof(auth));
    if (authSend < 0)
    {
        error("CLIENT: ERROR writing to socket-dec-client-auth:1");
    }
    // If received 'y' from server, client is dec_client
    // If received 'n' from server, client is not dec_client
    memset(auth, '\0', sizeof(auth));
    authRead = recvall(socketFD, auth, sizeof(auth));
    if (authRead < 0)
    {
        error("CLIENT: ERROR reading from socket");
    }
    if (strcmp(auth, "y") != 0)
    {
        error("ERROR connected client NOT dec_client");
    }

    // Send text file to server
    fd = fopen(argv[1], "r"); // Open text file for reading
    if (fd == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR could not open file %s \n", argv[1]);
        exit(1);
    }
    memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array for reuse
    // Read text file and send to server
    while ((textSize = fread(buffer, sizeof(char), BUFFER_SIZE, fd)) > 0)
    {
        nBytes = sendall(socketFD, buffer, BUFFER_SIZE);
        if (nBytes < 0)
        {
            error("CLIENT: ERROR writing to socket-dec-client-text:1");
            break;
        }
        memset(buffer, '\0', sizeof(buffer));
    }
    fclose(fd);

    // Send key file to server
    fd = fopen(argv[2], "r"); // Open text file for reading
    memset(buffer, '\0', sizeof(buffer));
    while ((keySize = fread(buffer, sizeof(char), BUFFER_SIZE, fd)) > 0)
    {
        // nBytes = send(socketFD, buffer, keySize, 0);
        nBytes = sendall(socketFD, buffer, BUFFER_SIZE);
        if (nBytes < 0)
        {
            error("CLIENT: ERROR writing to socket-dec-client-key:1");
            break;
        }
        memset(buffer, '\0', sizeof(buffer));
    }
    fclose(fd);

    // Get return message from server
    // Clear out the buffer again for reuse
    memset(buffer, '\0', sizeof(buffer));
    // Read data from the socket, leaving \0 at end
    charsRead = recvall(socketFD, buffer, BUFFER_SIZE);
    if (charsRead < 0)
    {
        error("CLIENT: ERROR reading from socket");
    }
    fprintf(stdout, "%s\n", buffer);

    // Close the socket
    close(socketFD);
    return 0;
}
