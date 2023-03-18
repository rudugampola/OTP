#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/wait.h>

#define BUFFER_SIZE 71680
#define ALPHABET_SIZE 27

/**
 * Encrypt Server Code
 * 1. Create a socket
 * 2. Bind the socket to an address
 * 3. Listen on the socket for connections
 * 4. Accept a connection
 * 5. Send/Receive
 * 6. Close the socket
 */

const char *CHAR_LIB = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

// Function to report errors
void error(const char *msg)
{
  perror(msg);
  exit(1);
}

// Return the position of c in charLib, -1 if c is not in charLib
int convertChar(char c)
{
  int i;
  for (i = 0; i < ALPHABET_SIZE; i++)
  {
    if (CHAR_LIB[i] == c)
    {
      return i;
    }
  }
  return -1;
}

// Return the char at position c of charLib
char convertInt(int c)
{
  return CHAR_LIB[c];
}

// Encrypt text using key and assign the result to cipher
void encrypt(char cipher[], const char text[], const char key[])
{
  int textLen = strlen(text);
  memset(cipher, '\0', BUFFER_SIZE);
  int textInt = 0;
  int keyInt = 0;
  int cipherInt = 0;
  int i;

  // Iterate through text and key, convert each char to int, add them together, and convert back to char
  for (i = 0; i < textLen-1; i++)
  {
    textInt = convertChar(text[i]);
    keyInt = convertChar(key[i]);
    // Mod 27 because we are appending ' ' to our alphabet
    cipherInt = (textInt + keyInt) % ALPHABET_SIZE;
    cipher[i] = convertInt(cipherInt);
  }
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
    // printf("Server-send: len: %d , bytesleft: %d \n", len, bytesleft);
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
 * 7.4 Handling Partial send()s section. 
 * https://beej.us/guide/bgnet/html/#sendrecv
*/
int recvall(int s, char *buf, int len) {
    int total = 0;         // how many bytes we've received so far
    int bytesleft = len;   // how many bytes we have left to receive
    int n;
    // printf("Server-recv: len: %d , bytesleft: %d \n", len, bytesleft);
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

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in *address, int portNumber)
{
  // Clear out the address struct
  memset((char *)address, '\0', sizeof(*address));

  // The address should be network capable
  address->sin_family = AF_INET;

  // Store the port number
  address->sin_port = htons(portNumber);

  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf(stderr, "USAGE: %s port\n", argv[0]);
    exit(1);
  }

  int connectionSocket, charsRead, authRead, authSend;
  char key[BUFFER_SIZE];
  char text[BUFFER_SIZE];
  char cipher[BUFFER_SIZE];
  char auth[2];
  pid_t pid;
  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  // Clear out the buffer, key, text, and cipher arrays
  memset(text, '\0', sizeof(text));
  memset(key, '\0', sizeof(key));
  memset(cipher, '\0', sizeof(cipher));

  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0)
  {
    error("ERROR opening socket");
  }

  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  // Associate the socket to the port
  if (bind(listenSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
  {
    error("ERROR on binding");
  }

  // Start listening for connetions. Allow up to 5 connections to queue up
  listen(listenSocket, 5);

  while (1)
  {
    // Accept a connection request and create a connection socket
    connectionSocket = accept(listenSocket, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
    if (connectionSocket < 0)
    {
      error("ERROR on accept");
    }

    // Fork a child process to handle the client connection
    pid_t pid = fork();
    if (pid < 0)
    {
      perror("ERROR on fork");
      exit(1);
    }
    if (pid == 0)
    {
      // Child process: authenticate client
      memset(auth, '\0', sizeof(auth));
      // recieve auth char from client and assign to auth
      authRead = recvall(connectionSocket, auth, sizeof(auth));
      if (authRead < 0)
      {
        error("ERROR reading from socket");
      }
      // if auth != e then the client is NOT enc_client and therefore invalid
      // return 'n' via connectionSocket to indicate this
      if (strcmp(auth, "e") != 0)
      {
        strcpy(auth, "n");
        authSend = sendall(connectionSocket, auth, sizeof(auth));
        if (authSend < 0)
        {
          error("ERROR writing to socket-enc-server-auth:1");
        }
      }
      // if auth == e then the client is enc_client and therefore valid
      // return 'y' via connectionSocket to indicate this
      else
      {
        strcpy(auth, "y");
        authSend = sendall(connectionSocket, auth, sizeof(auth));
        if (authSend < 0)
        {
          error("ERROR writing to socket-enc-server-auth:2");
        }
      }

      // Read the client's text from the socket
      charsRead = recvall(connectionSocket, text, BUFFER_SIZE);
      if (charsRead < 0)
      {
        error("ERROR reading from socket");
      }

      // Read the client's key from the socket
      charsRead = recvall(connectionSocket, key, BUFFER_SIZE);
      if (charsRead < 0)
      {
        error("ERROR reading from socket");
      }

      if (charsRead < 0)
      {
        error("ERROR reading from socket");
      }

      // Encrypt the text with the key
      encrypt(cipher, text, key);

      // Send the encrypted text back to the client
      charsRead = sendall(connectionSocket, cipher, BUFFER_SIZE);
      if (charsRead < 0)
      {
        error("ERROR writing to socket-enc-server-send:1");
      }

      // Close the connection socket for this client
      close(connectionSocket);
      exit(0);
    }
    else
    {
      // Parent process: wait for child to finish processing and then continue
      int childStatus;
      waitpid(pid, &childStatus, 0);
    }
  }

  // Close the listening socket
  close(listenSocket);
  return 0;
}
