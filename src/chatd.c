#define _GNU_SOURCE // we need accept4() from <sys/socket.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h> // O_NONBLOCK flag

#include "chat_common.h"


/* USEFUL WEBPAGES:
 * http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.7+Verifying+an+SSL+Peer+s+Certificate/
 * // how to prevent DoS like behavior/attack.
 * http://stackoverflow.com/questions/1744523/ssl-accept-with-blocking-socket
 *
 */

// useful macros
#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

// default keep-alive timeout for clients
#define KEEP_ALIVE_TIMEOUT 30


#define _AUTHENTICATED  0
#define _USER_CREATED   1
#define _AUTH_FAILED    2


#define SERVER_CERT_FILE "server.crt"
#define SERVER_KEY_FILE "server.key"


#define PASSWORDS_KEYFILE "passwords.ini"
static GKeyFile *keyfile;


// welcome message
static const char WELCOME_MSG[] = "Welcome";

// variable for buffering outcoming packets
// DON'T USE OUTSIDE build_and_send_packet() function !!!
static GString *packet;
static GString *temp_string;


static SSL_CTX *ssl_ctx; // encryption for sockets
static int sockfd; // master socket (server listening socket)
static GQueue *clients_queue;
static GQueue *clients_write_queue;



typedef struct ClientConnection {

	int num_of_tries;  // reminining number of tries to login
	GString *chatroom;     // chat room
	GString *username; // username after successful login
	GString *game_oponent;

	SSL *ssl;
	bool ssl_handshake_done;
	int conn_fd;
	GTimer *conn_timer;
	GTimer *login_timer;
	struct sockaddr_in client_sockaddr;
	GString *write_buffer;
	GString *cookie_token;
} ClientConnection;


/* Function for printing log messages to output. */
void log_msg(ClientConnection *connection, char *message)
{
	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char iso_8601[] = "YYYY-MM-DDThh:mm:ssTZD";
	strftime(iso_8601, sizeof iso_8601, "%FT%T%Z", now_tm);

	printf("%s : %s:%d %s\n", iso_8601, inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), message);

	fflush(stdout);
}


/* When a new client wishes to establish a connection, we create the connection and add it to the queue */
ClientConnection* new_ClientConnection(int conn_fd)
{
	ClientConnection *connection = g_new0(ClientConnection, 1);
	// find out client IP and port
	int addrlen = sizeof(connection->client_sockaddr);
	getpeername(conn_fd, (struct sockaddr*)&(connection->client_sockaddr), (socklen_t*)&addrlen);

	connection->conn_fd = conn_fd;
	connection->conn_timer = g_timer_new();

	connection->login_timer = NULL;

	connection->cookie_token = g_string_new(NULL);
	connection->write_buffer = g_string_new(NULL);

	connection->chatroom = g_string_new(NULL);
	connection->username = g_string_new(NULL);
	connection->game_oponent = g_string_new(NULL);
	connection->num_of_tries = 3;

	connection->ssl_handshake_done = false;
	connection->ssl = SSL_new(ssl_ctx);
	SSL_set_accept_state(connection->ssl);

	/* Use encryption during connection. */
	SSL_set_fd(connection->ssl, conn_fd);

	g_queue_push_tail(clients_queue, connection);

	return connection;
}


/* Destroy/close/free instance of ClientConnection.
   @connection has to be allocated by malloc() */
void destroy_ClientConnection(ClientConnection *connection)
{
	log_msg(connection, "disconnected");
	SSL_shutdown(connection->ssl);
	SSL_free(connection->ssl);
	close(connection->conn_fd); // close socket with client connection
	g_timer_destroy(connection->conn_timer); // destroy timer
	if (connection->login_timer)
		g_timer_destroy(connection->login_timer); // destroy timer
	g_string_free(connection->cookie_token, TRUE);
	g_string_free(connection->write_buffer, TRUE);
	g_string_free(connection->chatroom, TRUE);
	g_string_free(connection->username, TRUE);
	g_string_free(connection->game_oponent, TRUE);
	g_free(connection); // free memory allocated for this instance of ClientConnection
}

/* Takes a connection from the queue and runs destroy_ClientConnection function */
void remove_ClientConnection(ClientConnection *connection)
{
	destroy_ClientConnection(connection);
	if (!g_queue_remove(clients_queue, connection)) {
		printf("Something is wrong. Connection was not found in queue.\n");
	}
	g_queue_remove(clients_write_queue, connection); // just in case the connection was in this queue
}

/* Runs through the queue of clients and runs remove_ClientConnection for every instance in it,
   then frees the memory */
void destroy_clients_queue(GQueue *clients_queue)
{
	g_queue_foreach(clients_queue, (GFunc) remove_ClientConnection, NULL);
	g_queue_free(clients_queue);
}


/* Closes the connection of both socket and file writer, runs destroy_clients_queue function and exits program */
void clean_and_die(int exit_code)
{
	/* Close the connections. */
	// http://stackoverflow.com/questions/4160347/close-vs-shutdown-socket
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
	SSL_CTX_free(ssl_ctx);
	EVP_cleanup();

	//fclose(log_file);

	printf("Closing %d connections.\n", clients_queue->length);

	destroy_clients_queue(clients_queue);
	clients_queue = NULL;
	g_queue_free(clients_write_queue);
	clients_write_queue = NULL;

	g_string_free(packet, TRUE);
	g_string_free(temp_string, TRUE);

	// save passwords into file
	gsize length;
	gchar *keyfile_string = g_key_file_to_data(keyfile, &length, NULL);

	FILE * passwd_file;
	if ((passwd_file = fopen(PASSWORDS_KEYFILE, "w")) != NULL) {
		fwrite (keyfile_string , sizeof(gchar), length, passwd_file);
		fclose(passwd_file);
	}
	else {
		fprintf(stderr, "Problem occured while trying to save password database into %s.\n", PASSWORDS_KEYFILE);
	}
	g_free(keyfile_string);
	g_key_file_free(keyfile);

	exit(exit_code);
}


/* Signal handler function that closes down program, by running clean_and_die function */
void sig_handler(int signal_n)
{
	if (signal_n == SIGINT) {
		printf("\nShutting down...\n");
	}
	clean_and_die(0);
}


/* Encrypt packet and try to send it through ssl connection.
 */
bool send_packet(ClientConnection *connection, char *packet, int len)
{
	ERR_clear_error();
	int n = SSL_write(connection->ssl, packet, len);
	int error = SSL_get_error(connection->ssl, n);

	switch (error) {
		case SSL_ERROR_NONE:
			if (n == len) {
				//printf("whole packet sent successfully\n");
				g_queue_remove(clients_write_queue, connection);
				g_string_truncate(connection->write_buffer, 0);
				return true;
			}
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			if (!g_queue_find(clients_write_queue, connection))
				g_queue_push_tail(clients_write_queue, connection);
				g_string_assign(connection->write_buffer, packet);
			return true;
		default:
			// perror("SSL_write error");
			// probably closed connection
			return false;
	}
}


void build_and_send_packet(ClientConnection *connection, const int opcode, const char *message)
{
	g_string_truncate(packet, 0);

	// write opcode in binary form at the start of the packet
	g_string_append_len(packet, (char *)(&opcode), sizeof(int));
	g_string_append(packet, message);

	send_packet(connection, packet->str, packet->len);
}


/* Add child socket to set */
void add_socket_into_set(ClientConnection *connection, fd_set *readfds_ptr)
{
	FD_SET(connection->conn_fd, readfds_ptr);
}

/* A helper function to find the connection with highest sockfd */
void max_sockfd(ClientConnection *connection, int *max)
{
	*max = max(connection->conn_fd, *max);
}

/* Runs max_sockfd for every client in queue and returns the higest value */
int return_max_sockfd_in_queue(GQueue *clients_queue)
{
	int max = 0;
	g_queue_foreach(clients_queue, (GFunc) max_sockfd, &max);
	return max;
}


/* Check timer of the connection and close/destroy connection if time exceeded KEEP_ALIVE_TIMEOUT seconds */
void check_timer(ClientConnection *connection)
{

	gdouble seconds_elapsed = g_timer_elapsed(connection->conn_timer, NULL);
	if (seconds_elapsed >= MAX_IDLE_TIME) {
		log_msg(connection, "timed out.");
		destroy_ClientConnection(connection);
		if (!g_queue_remove(clients_queue, connection)) {
			printf("Something is wrong. Connection was not found in queue.\n");
		}
	}
}

// check if client is logged in - if not, send him error message
bool user_logged_in(ClientConnection *client) {
	if (client->username->len == 0) {
		build_and_send_packet(client, ERROR, "You must log in first. Use '/user <username>'.");
		return false;
	}
	return true;
}

// check if client is a member of any room -  if not, send him error message
bool user_member_of_chatroom(ClientConnection *client) {
	if (client->chatroom->len == 0) {
		build_and_send_packet(client, ERROR, "You are not a member of any room. Use '/join <room>' to join some room or to create new one.");
		return false;
	}
	return true;
}

// send info about connection to requester (username, ip:port, room)
void send_user_info(ClientConnection *connection, ClientConnection *recipient)
{
	g_string_printf(temp_string, "%-20s| %s : %-8d | %s",
			connection->username->str,
			inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port),
			connection->chatroom->str);
	build_and_send_packet(recipient, INFO, temp_string->str);
}

// send list of all connections (username, ip:port, room) to requester
void send_list_of_all_users(ClientConnection *connection)
{
	g_string_assign(temp_string, "USERNAME            |     IP    : PORT     | CHATROOM");
	build_and_send_packet(connection, INFO, temp_string->str);
	g_string_assign(temp_string, "-----------------------------------------------------");
	build_and_send_packet(connection, INFO, temp_string->str);

	g_queue_foreach(clients_queue, (GFunc) send_user_info, connection);
}

// helper structure for passing more arguments into function called by foreach cycle
typedef struct room_and_its_presence_in_queue
{
	GString *room;
	bool room_already_in_queue;
} RoomInQueue;


// GFunc for foreach cycle - this function is called for every element in the queue
void is_room_in_queue(GString *room_in_queue, RoomInQueue *new_room)
{
	if (g_string_equal(room_in_queue, new_room->room))
		new_room->room_already_in_queue = true;
}

// add client (connection) room to the queue (if client is in some room and if room is not present in queue)
void add_room_to_list(ClientConnection *connection, GQueue *room_queue)
{
	// if this connection is not member of any room, skip
	if (connection->chatroom->len == 0)
		return;

	// just helper structure to pass two arguments into next foreach cycle
	RoomInQueue new_room = {connection->chatroom, false};

	// check room_queue if room is already there
	g_queue_foreach(room_queue, (GFunc) is_room_in_queue, &new_room);

	// add room into room_queue if it is not yet there
	if (!new_room.room_already_in_queue)
		g_queue_push_tail(room_queue, connection->chatroom);
}

// send list of all rooms to requester
void send_list_of_all_rooms(ClientConnection *connection)
{
	GQueue *room_queue = g_queue_new();
	g_queue_foreach(clients_queue, (GFunc) add_room_to_list, room_queue);

	g_string_assign(temp_string, "List of all rooms: ");
	GString *room_p;
	while ((room_p = g_queue_pop_head (room_queue)) != NULL) {
		g_string_append(temp_string, room_p->str);
		if (g_queue_peek_head(room_queue)) {
			g_string_append(temp_string, ", ");
		}
	}
	build_and_send_packet(connection, INFO, temp_string->str);
	g_queue_free(room_queue);
}


// assign connection (client) to the @room
void join_chat_room(ClientConnection *connection, const char *room)
{
	if (user_logged_in(connection)) { // check if user is logged in
		g_string_printf(temp_string, "joined room [%s]", room);
		log_msg(connection, temp_string->str);
		g_string_assign(connection->chatroom, room);
		build_and_send_packet(connection, CHANGE_ROOM, room);
	}
}

typedef struct
{
	GString *username;
	ClientConnection *client;
} UsernameAndClient;

void username_to_connection(ClientConnection *connection, UsernameAndClient *wanted)
{
	if (g_string_equal(connection->username, wanted->username)) {
		wanted->client = connection;
	}
}


/*  Random string generator */
void random_string(unsigned char *string, size_t length)
{
	static char charset[] = "0123456789"
				"abcdefghijklmnopqrstuvwxyz"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/* Seed number for rand() */
	srand((unsigned int) time(0));

	while (length-- > 0) {
		size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
		*string++ = charset[index];
	}
	*string = '\0';
}



int authenticate(const char *username, const char *password)
{
	gchar *hash_passwd64_from_db, *hash_salt64_from_db;
	gsize length;

	hash_passwd64_from_db = g_key_file_get_string(keyfile, "passwords", username, NULL);
	hash_salt64_from_db = g_key_file_get_string(keyfile, "salts", username, NULL);

	unsigned char salt[MAX_PASSWORD_LENGTH];
	if (hash_salt64_from_db) { // user was found in database
		// loading salt from file
		guchar *hash_salt_from_db = g_base64_decode(hash_salt64_from_db, &length); // salt was base64 coded - decode it
		strncpy((char*)salt, (char*)hash_salt_from_db, sizeof(salt)); // copy decoded string from db to local variable
		g_free(hash_salt_from_db); // deallocating result of decode function
		if (length != MAX_PASSWORD_LENGTH) // if nobody touched the file, sizes should equal
			fprintf(stderr, "ERR: salt length after decoding != MAX_PASSWORD_LENGTH.\n");
		if (!hash_passwd64_from_db)
			fprintf(stderr, "ERR: hash found in file, but password not. '%s' is inconsistent.\n", PASSWORDS_KEYFILE);
	}
	else
		random_string(salt, MAX_PASSWORD_LENGTH);

	unsigned char hash_passwd[SIZE_OF_HASH];
	if(!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, sizeof(salt), HASH_ITERATION, sizeof(hash_passwd), hash_passwd) != 0 ) {
		// ERROR
		fprintf(stderr, "ERR: PKCS5_PBKDF2_HMAC_SHA1 failed, something is wrong. Please investigate.\n");
		return _AUTH_FAILED;
	}
	gchar *hash_passwd64_new = g_base64_encode(hash_passwd, sizeof(hash_passwd));

	if (hash_passwd64_from_db) { // if user was found in database
		// compare hashes
		if (strcmp(hash_passwd64_from_db, hash_passwd64_new) == 0) {
			// password match
			return _AUTHENTICATED;
		}
		else { // passwords differ
			return _AUTH_FAILED;
		}
	}
	else { // user was not found in database, create new user
		gchar *hash_salt64_new = g_base64_encode(salt, sizeof(salt));
		g_key_file_set_string(keyfile, "passwords", username, hash_passwd64_new);
		g_key_file_set_string(keyfile, "salts", username, hash_salt64_new);
		g_free(hash_salt64_new);
	}

	g_free(hash_passwd64_from_db);
	g_free(hash_salt64_from_db);
	g_free(hash_passwd64_new);

	return _USER_CREATED;
}


void login_user(ClientConnection *connection, const char *username, const char *password)
{
	UsernameAndClient username_and_client = {NULL, NULL};
	username_and_client.username = g_string_new(username);

	g_queue_foreach(clients_queue, (GFunc) username_to_connection, &username_and_client);
	ClientConnection *logged_client = username_and_client.client;

	if (logged_client) {
		g_string_printf(temp_string, "User [%s] is already logged in. Contact administrator of chat services in case you want to kick him out.", username);
		build_and_send_packet(connection, ERROR, temp_string->str);
		return;
	}

	if (connection->login_timer) { // if timer was created
		gdouble seconds_elapsed_from_last_failed_login = g_timer_elapsed(connection->login_timer, NULL);
		if (seconds_elapsed_from_last_failed_login < 5) {
			g_string_printf(temp_string, "You have to wait %d seconds and then you can try to log in again.", (int) seconds_elapsed_from_last_failed_login);
			build_and_send_packet(connection, ERROR, temp_string->str);
			return;
		}
	}

	// try to authenticate
	switch(authenticate(username, password)) {
		case _AUTHENTICATED:
			g_string_assign(connection->username, username);
			build_and_send_packet(connection, LOGGED_IN, username);

			g_string_printf(temp_string, "authenticated [%s]", username);
			log_msg(connection, temp_string->str);
			connection->num_of_tries = 3; // reset counter for attempts to login
			break;
		case _AUTH_FAILED: // authentication failed
			log_msg(connection, "authentication error");

			if ((--connection->num_of_tries) == 0) {
				build_and_send_packet(connection, ERROR, "Maximum number of login attempts reached. You will be disconnected!");
				remove_ClientConnection(connection);
				return;
			}
			g_string_printf(temp_string, "Authentication failed (wrong password). Remaining tries: %d.", connection->num_of_tries);
			build_and_send_packet(connection, ERROR, temp_string->str);
			if (connection->login_timer == NULL)
				connection->login_timer = g_timer_new();
			else
				g_timer_start(connection->login_timer); // reset timer
			break;
		case _USER_CREATED:
			g_string_assign(connection->username, username);
			build_and_send_packet(connection, USER_CREATED, username);

			g_string_printf(temp_string, "authenticated [%s] (new user created)", username);
			log_msg(connection, temp_string->str);
			connection->num_of_tries = 3; // reset counter for attempts to login
			break;
	}
}


void send_private_message(ClientConnection *sender, const char *recipient, const char *message)
{
	if (user_logged_in(sender)) { // check if user is logged in

		UsernameAndClient recipient_struct = {NULL, NULL};
		recipient_struct.username = g_string_new(recipient);
		// find recipient between connections
		g_queue_foreach(clients_queue, (GFunc) username_to_connection, &recipient_struct);
		ClientConnection *recipient_connection = recipient_struct.client;

		if (recipient_connection) { // recipient does exist
			// send message to sender back (confirm that it was delivered and show on the screen)
			g_string_printf(temp_string, "%s %s", recipient_connection->username->str, message);
			build_and_send_packet(sender, PRIVATE_MESSAGE_SENT, temp_string->str);

			// send message to recipient privately
			g_string_printf(temp_string, "%s %s", sender->username->str, message);
			build_and_send_packet(recipient_connection, PRIVATE_MESSAGE_RECEIVED, temp_string->str);
		}
		else { // recipient does not exist
			g_string_printf(temp_string, "User [%s] does not exist or is currently not logged in.", recipient);
			build_and_send_packet(sender, ERROR, temp_string->str);
		}
	}
}


typedef struct
{
	GString *room;
	GString *message;
} RoomAndMessage;


// send packet to client if he is in the room where message was sent
void send_message_if_connection_in_chatroom(ClientConnection *connection, RoomAndMessage *room_and_message)
{
	if (g_string_equal(connection->chatroom, room_and_message->room))
		build_and_send_packet(connection, ROOM_MESSAGE, room_and_message->message->str);
}


// send message to each client in the room where the client is (if any)
void send_message(ClientConnection *sender, const char *message)
{
	if (user_logged_in(sender)) { // check if user is logged in
		if (user_member_of_chatroom(sender)) { // check if user is a member of any chatroom
			// build message string
			g_string_printf(temp_string, "%s %s", sender->username->str, message);
			RoomAndMessage room_and_message = {sender->chatroom, temp_string};
			// send message to every client which is inside the room
			g_queue_foreach(clients_queue, (GFunc) send_message_if_connection_in_chatroom, &room_and_message);
		}
	}
}





void game(ClientConnection *challenger, const char *challenged_user)
{
	if (!user_logged_in(challenger)) // check if user is logged in
		return;

	if (strcmp(challenger->username->str, challenged_user) == 0) {
		build_and_send_packet(challenger, ERROR, "You cannot challenge yourself.");
		return;
	}

	UsernameAndClient username_and_client = {NULL, NULL};
	username_and_client.username = g_string_new(challenged_user);

	g_queue_foreach(clients_queue, (GFunc) username_to_connection, &username_and_client);
	ClientConnection *challenged_client = username_and_client.client;

	if (challenged_client) { // challenged client was found
		if (challenged_client->game_oponent->len != 0) {
			// user is currently in another challenge, cannot be challenged
			g_string_printf(temp_string, "User [%s] is currently in another challenge.", challenged_client->username->str);
			build_and_send_packet(challenger, ERROR, temp_string->str);
		}
		else { // user can be challenged
			g_string_assign(challenged_client->game_oponent, challenger->username->str);

			// send message to challenged client
			build_and_send_packet(challenged_client, CHALLENGE, challenger->username->str);

			// send message to challenger
			g_string_printf(temp_string, "User [%s] was challengd. Waiting for acceptance.", challenged_client->username->str);
			build_and_send_packet(challenger, INFO, temp_string->str);

			// log message
			g_string_printf(temp_string, "challenge sent to [%s]", challenged_client->username->str);
			log_msg(challenger, temp_string->str);
		}
	}
	else { // challenged user was not found
		g_string_printf(temp_string, "User [%s] was not found.", challenged_user);
		build_and_send_packet(challenger, ERROR, temp_string->str);
	}
	g_string_free(username_and_client.username, TRUE);
}


void roll(ClientConnection *connection)
{
	build_and_send_packet(connection, ERROR, "not yet implemented");
}


void accept_game(ClientConnection *connection)
{
	if (!user_logged_in(connection)) // check if user is logged in
		return;

	if (connection->game_oponent->len == 0) {
		// if client was not challenged, send him back error
		build_and_send_packet(connection, ERROR, "You have not been challenged to any game.");
	} else {
		// client was challenged
		UsernameAndClient username_and_client = {connection->game_oponent, NULL};
		g_queue_foreach(clients_queue, (GFunc) username_to_connection, &username_and_client);
		ClientConnection *oponent = username_and_client.client;

		if (oponent) { // challenger (oponent) is still connected

			// send message to client that accepted the game
			g_string_printf(temp_string, "You have accepted a game from [%s]. Use /roll to generate a number.", oponent->username->str);
			build_and_send_packet(connection, INFO, temp_string->str);

			// send message to challenger
			g_string_printf(temp_string, "User [%s] accepted your game. Use /roll to generate a number.", connection->username->str);
			build_and_send_packet(oponent, INFO, temp_string->str);

			// log message
			log_msg(connection, "accepted game");
		}
		else { // challenger (oponent) was disconnected in the meantime
			// send message to client that tried to accept the game
			g_string_printf(temp_string, "User [%s] is not connected yet.", connection->game_oponent->str);
			build_and_send_packet(connection, ERROR, temp_string->str);
			g_string_truncate(connection->game_oponent, 0);
		}
	}
}


void decline_game(ClientConnection *connection)
{
	if (!user_logged_in(connection)) // check if user is logged in
		return;

	if (connection->game_oponent->len == 0) {
		// if client was not challenged, send him back error
		build_and_send_packet(connection, ERROR, "You have not been challenged to any game.");
	} else {
		// client was challenged
		UsernameAndClient username_and_client = {connection->game_oponent, NULL};
		g_queue_foreach(clients_queue, (GFunc) username_to_connection, &username_and_client);
		ClientConnection *oponent = username_and_client.client;

		if (oponent) { // challenger (oponent) is still connected

			// send message to client that declined the game
			g_string_printf(temp_string, "You have declined a game from [%s].", oponent->username->str);
			build_and_send_packet(connection, ERROR, temp_string->str);

			// send message to challenger
			g_string_printf(temp_string, "User [%s] declined your game.", connection->username->str);
			build_and_send_packet(oponent, ERROR, temp_string->str);

			// log message
			log_msg(connection, "declined game");
			g_string_truncate(connection->game_oponent, 0);
		}
		else { // challenger (oponent) was disconnected in the meantime
			// send message to client that tried to decline the game
			g_string_printf(temp_string, "User [%s] is not connected yet.", connection->game_oponent->str);
			build_and_send_packet(connection, ERROR, temp_string->str);
			g_string_truncate(connection->game_oponent, 0);
		}
	}
}


void send_test_message(ClientConnection *connection)
{
	build_and_send_packet(connection, ROOM_MESSAGE, "username message");
}


void parse_client_message(ClientConnection *connection, GString *received_packet)
{
	int opcode = *((int *)received_packet->str);
	char *message = received_packet->str + sizeof(int); // packet without opcode

/*
	WHO,      //  /who          # list of all users
	LIST,     //  /list         # list of all rooms
	JOIN,     //  /join <room>
	USER,     //  /user <username> <password>    # login
	SAY,      //  /say <username> <msg>          # private message
	//BYE,    //  /bye   # maybe just close the connection after this command
	MSG,      //  <MSG_opcode> <message>
	GAME,     //  /game <username>
	ROLL,     //  /roll
	ACCEPT,   //  /accept
	DECLINE   //  /decline
*/
	switch(opcode) {
		case WHO:
			send_list_of_all_users(connection);
			break;
		case LIST:
			send_list_of_all_rooms(connection);
			break;
		case JOIN:
			join_chat_room(connection, message);
			break;
		case USER:
		case SAY: ; // empty statement
			gchar **msg = g_strsplit(message, " ", 2); // split into username and message
			if (g_strv_length(msg) == 2) {
				const char *user = msg[0];
				if (opcode == USER) { // user trying to login
					const char *passwd = msg[1];
					login_user(connection, user, passwd);
				} else { // opcode == SAY (private message)
					send_private_message(connection, user, msg[1]);
				}
			}
			else
				printf("Corrupted packet !!\n");
			g_strfreev(msg);
			break;
		case MSG:
			send_message(connection, message);
			break;
		case GAME:
			game(connection, message);
			break;
		case ROLL:
			roll(connection);
			break;
		case ACCEPT:
			accept_game(connection);
			break;
		case DECLINE:
			decline_game(connection);
			break;

	}
}


bool try_to_perform_ssl_handshake (ClientConnection *connection)
{
	ERR_clear_error();
	int ret = SSL_accept(connection->ssl);
	if (ret == 1) {
		// SSL handshake was successful
		connection->ssl_handshake_done = true;
		log_msg(connection, "connected");
		return true;
	}
	else {
		// SSL handshake was not successful, try to figure out what did happen
		int error = SSL_get_error(connection->ssl, ret);
		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
			// operation did not complete the action, should be called again
			return false;
		} else {
			log_msg(connection, "SSL handshake failed");
			char buf[120];
			ERR_error_string_n(error, buf, sizeof(buf));
			//printf("SSL_connect() return value: %d\n", ret);
			//printf("SSL_get_error(): %d\n", error);
			//printf("ERR_error_string_n(): %s\n", buf);

			remove_ClientConnection(connection);
			return false;
		}
	}
}






/* Processes the request of client and builds a response,
   using recieve_whole_message, parse_request, create_html_page and log_msg */
void handle_connection(ClientConnection *connection)
{
	g_timer_start(connection->conn_timer); // reset timer

	// if SSL handshake was not performed yet
	if (!connection->ssl_handshake_done) {
		if (try_to_perform_ssl_handshake(connection)) {
			build_and_send_packet(connection, INFO, "Welcome");
		}
		return;
	}

	// Receiving packet from socket
	GString *received_message = g_string_sized_new(MAX_PACKET_SIZE);
	if (!recv_packet(connection->ssl, received_message)) {
		// message was not received or has length 0
		remove_ClientConnection(connection);
		return;
	}

	// parse message from client
	parse_client_message(connection, received_message);

	g_string_free(received_message, TRUE);
	return;
}



/* check if socket is in the set of waiting sockets and handle connection if it is */
void handle_socket_if_waiting(ClientConnection *connection, fd_set *readfds)
{
	if (FD_ISSET(connection->conn_fd, readfds)) {
		handle_connection(connection);
	}
}


/* check if there is a socket ready for writing and send write_buffer to client */
void send_message_if_ready(ClientConnection *connection, fd_set *writefds)
{
	if (FD_ISSET(connection->conn_fd, writefds)) {
		send_packet(connection, connection->write_buffer->str, connection->write_buffer->len);
	}
}


/* A looping function that waits for incoming connection, adds it
   to the queue and attempts to processes all clients waiting in the queue */
void run_loop()
{
	struct sockaddr_in client;
	int max_sockfd;

	//cookies = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	fd_set readfds;
	fd_set writefds;
	while(42) {
		struct timeval tv;
		// every second check all timers - for purposes of handling keep-alive timeout
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		//clear the socket sets
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		//add master socket to set
		FD_SET(sockfd, &readfds);
		max_sockfd = max(sockfd, return_max_sockfd_in_queue(clients_queue));
		max_sockfd = max(max_sockfd, return_max_sockfd_in_queue(clients_write_queue));

		//add child sockets to sets
		g_queue_foreach(clients_queue, (GFunc) add_socket_into_set, &readfds);
		g_queue_foreach(clients_write_queue, (GFunc) add_socket_into_set, &writefds);

		int retval = select(max_sockfd + 1, &readfds, &writefds, NULL, &tv);
		if (retval < 0) {
			perror("select error");
			return;

		}
		else if (retval == 0) { // timeout
			g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);

			//g_queue_foreach(clients_queue, (GFunc) send_test_message, NULL);
			continue;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			//If something happened on the master socket , then its an incoming connection
			socklen_t len = (socklen_t) sizeof(client);
			// accept new client & set the O_NONBLOCK file status flag on the created socket
			int conn_fd = accept4(sockfd, (struct sockaddr *) &client, &len, O_NONBLOCK);
			if (conn_fd < 0) {
				perror("Unable to accept()");
				return;
			}

			//add new client into the queue
			ClientConnection *new_client = new_ClientConnection(conn_fd);

			log_msg(new_client, "new connection");

			handle_connection(new_client);
		}

		g_queue_foreach(clients_queue, (GFunc) handle_socket_if_waiting, &readfds);

		g_queue_foreach(clients_write_queue, (GFunc) send_message_if_ready, &writefds);

		// check timer of every connection in queue
		g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);

	}
}



/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;

	/* If either of the pointers is NULL or the addresses
	   belong to different families, we abort. */
	g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
			(_addr1->sin_family != _addr2->sin_family));

	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
		return -1;
	} else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
		return 1;
	} else if (_addr1->sin_port < _addr2->sin_port) {
		return -1;
	} else if (_addr1->sin_port > _addr2->sin_port) {
		return 1;
	}
	return 0;
}


/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
	return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}

bool initialize_openssl()
{
	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_server_method());

	if(!ssl_ctx) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	/* Load server certificate into the SSL context */
	if (SSL_CTX_use_certificate_file(ssl_ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	/* Load the server private-key into the SSL context */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		fprintf(stderr, "Private key doesn't match the certificate.\n");
		return false;
	}

	// setting up verification flags
	// SSL_VERIFY_NONE - no request for a certificate is sent to the client
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); // NULL = built-in default verification function will be used

	return true;
}


bool start_listening(int server_port)
{
	struct sockaddr_in server;

	/* Create and bind a TCP socket */
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == 0) {
		perror("socket() failed");
		return false;
	}

	// setting up flag SO_REUSEADDR for server socket
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");


	/* Network functions need arguments in network byte order instead of
	   host byte order. The macros htonl, htons convert the values. */
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(server_port);

	if (bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server)) < 0) {
		perror("bind() failed");
		return false;
	}

	/* Before the server can accept messages, it has to listen to the
	   welcome port.*/
	printf("Listening on port %d \n", server_port);
	listen(sockfd, 10);
	printf("Waiting for connections ...\n\n");

	return true;
}


bool file_exists(const char * filename)
{
	FILE * file;
	if ((file = fopen(filename, "r")) != NULL) {
		fclose(file);
		return true;
	}
	return false;
}


bool load_keyfile()
{
	keyfile = g_key_file_new();

	if (file_exists(PASSWORDS_KEYFILE)) {
		GError *error;
		if (!g_key_file_load_from_file(keyfile, PASSWORDS_KEYFILE, G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error)) {
			g_debug("%s", error->message);
			printf("Keyfile '%s' is corrupted.\n", PASSWORDS_KEYFILE);
			return false;
		}
	}
	return true;
}




int main(int argc, char **argv)
{

	if (!load_keyfile())
		return EXIT_FAILURE;

	errno = 0; // reset
	packet = g_string_sized_new(MAX_PACKET_SIZE);
	temp_string = g_string_sized_new(MAX_PACKET_SIZE);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const int server_port = strtol(argv[1], NULL, 10);

	// catch SIGINT
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		printf("\nCannot catch SIGINT!\n");

	// create queue for storing client connections
	clients_queue = g_queue_new();
	clients_write_queue = g_queue_new();

	// OPENSSL initialization
	if (!initialize_openssl()) {
		clean_and_die(EXIT_FAILURE);
	}

	// create socket and start listening
	if (!start_listening(server_port)) {
		clean_and_die(EXIT_FAILURE);
	}

	run_loop();

	clean_and_die(0);
}
