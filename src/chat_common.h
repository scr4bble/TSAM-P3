#include <stdbool.h>
#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>


#define MAX_PACKET_SIZE 1000 // maximum size of packet sent by server/client in bytes
#define MAX_IDLE_TIME 180 // in seconds
#define MAX_USERNAME_LENGTH 32 // characters
#define MAX_PASSWORD_LENGTH 32 // characters


bool read_message(SSL *ssl, GString *message);


// CLIENT_TO_SERVER_OPCODES
typedef enum {
	WHO,      //  /who          # list of all users
	LIST,     //  /list         # list of all rooms
	JOIN,     //  /join <room>
	USER,     //  /user <username> <password>    # login
	SAY,      //  /say <username> <msg>          # private message
	//BYE,    //  /bye   # maybe just close the connection after this command
	MSG,
	GAME,     //  /game <username>
	ROLL,     //  /roll
	ACCEPT,   //  /accept
	DECLINE   //  /decline
} CLIENT_TO_SERVER_OPCODES;


// SERVER_TO_CLIENT_OPCODES
typedef enum {
	ERROR,            // for example - room does not exist, username does not exist, bad password, etc.
	CHANGE_ROOM,      // after receiving this message client can set up internal variable with room
	LOGGED_IN,        // after receiving this message client can set up internal variable with username
	MESSAGE,          // just print out message from server (room message) "<OPCODE><USERNAME> <MESSAGE>"
	PRIVATE_MESSAGE,  // private message (client should print that in different way from room messages) "<OPCODE><USERNAME> <MESSAGE>"
	CHALLENGE         // challenge from another user (game)
} SERVER_TO_CLIENT_OPCODES;
