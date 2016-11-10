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


#define SERVER_CERT_FILE "../server.crt"
#define SERVER_KEY_FILE "../server.key"


// welcome message
static const char WELCOME_MSG[] = "Welcome";

static SSL_CTX *ssl_ctx; // encryption for sockets
static int sockfd; // master socket (server listening socket)
static GQueue *clients_queue;
static GQueue *clients_write_queue;
//static GHashTable* cookies;




typedef struct ClientConnection {

	// int num_of_tries;  // reminining number of tries to login
	// GString *room;     // chat room
	// GString *username; // username after successful login

	SSL *ssl;
	bool ssl_handshake_done;
	int conn_fd;
	GTimer *conn_timer;
	struct sockaddr_in client_sockaddr;
	GString *write_buffer;
	GString *cookie_token;
} ClientConnection;


/* Function for printing log messages to output. */
void log_msg(ClientConnection *connection, char *message) {

	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char iso_8601[] = "YYYY-MM-DDThh:mm:ssTZD";
	strftime(iso_8601, sizeof iso_8601, "%FT%T%Z", now_tm);

	printf("%s : %s:%d %s\n", iso_8601, inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), message);
}


/* When a new client wishes to establish a connection, we create the connection and add it to the queue */
ClientConnection* new_ClientConnection(int conn_fd) {
	ClientConnection *connection = g_new0(ClientConnection, 1);
	// find out client IP and port
	int addrlen = sizeof(connection->client_sockaddr);
	getpeername(conn_fd, (struct sockaddr*)&(connection->client_sockaddr), (socklen_t*)&addrlen);

	connection->conn_fd = conn_fd;
	connection->conn_timer = g_timer_new();
	connection->cookie_token = g_string_new(NULL);
	connection->write_buffer = g_string_new(NULL);

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
void destroy_ClientConnection(ClientConnection *connection) {

	log_msg(connection, "disconnected");
	SSL_shutdown(connection->ssl);
	SSL_free(connection->ssl);
	close(connection->conn_fd); // close socket with client connection
	g_timer_destroy(connection->conn_timer); // destroy timer
	g_string_free(connection->cookie_token, TRUE);
	g_string_free(connection->write_buffer, TRUE);
	g_free(connection); // free memory allocated for this instance of ClientConnection
}

/* Takes a connection from the queue and runs destroy_ClientConnection function */
void remove_ClientConnection(ClientConnection *connection) {
	destroy_ClientConnection(connection);
	if (!g_queue_remove(clients_queue, connection)) {
		printf("Something is wrong. Connection was not found in queue.\n");
	}
}

/* Runs through the queue of clients and runs remove_ClientConnection for every instance in it,
   then frees the memory */
void destroy_clients_queue(GQueue *clients_queue) {
	g_queue_foreach(clients_queue, (GFunc) remove_ClientConnection, NULL);
	g_queue_free(clients_queue);
}


/* Closes the connection of both socket and file writer, runs destroy_clients_queue function and exits program */
void clean_and_die(int exit_code) {

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

	//g_hash_table_destroy(cookies);

	exit(exit_code);
}


/* Signal handler function that closes down program, by running clean_and_die function */
void sig_handler(int signal_n) {
	if (signal_n == SIGINT) {
		printf("\nShutting down...\n");
	}
	clean_and_die(0);
}


/* Encrypt message and try to send it through ssl connection.
 */
bool write_message(ClientConnection *connection, char *message, int len) {

	ERR_clear_error();
	int n = SSL_write(connection->ssl, message, len);
	int error = SSL_get_error(connection->ssl, n);

	switch (error) {
		case SSL_ERROR_NONE:
			if (n == len) {
				//printf("whole message sent successfully\n");
				g_queue_remove(clients_write_queue, connection);
				g_string_truncate(connection->write_buffer, 0);
				return true;
			}
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			if (!g_queue_find(clients_write_queue, connection))
				g_queue_push_tail(clients_write_queue, connection);
				g_string_assign(connection->write_buffer, message);
			return true;
		default:
			// perror("SSL_write error");
			// probably closed connection
			return false;
	}
}



/* Add child socket to set */
void add_socket_into_set(ClientConnection *connection, fd_set *readfds_ptr) {
	FD_SET(connection->conn_fd, readfds_ptr);
}

/* A helper function to find the connection with highest sockfd */
void max_sockfd(ClientConnection *connection, int *max) {
	*max = max(connection->conn_fd, *max);
}

/* Runs max_sockfd for every client in queue and returns the higest value */
int return_max_sockfd_in_queue(GQueue *clients_queue) {
	int max = 0;
	g_queue_foreach(clients_queue, (GFunc) max_sockfd, &max);
	return max;
}



/* Check timer of the connection and close/destroy connection if time exceeded KEEP_ALIVE_TIMEOUT seconds */
void check_timer(ClientConnection *connection) {

	gdouble seconds_elapsed = g_timer_elapsed(connection->conn_timer, NULL);
	if (seconds_elapsed >= MAX_IDLE_TIME) {
		log_msg(connection, "timed out.");
		destroy_ClientConnection(connection);
		if (!g_queue_remove(clients_queue, connection)) {
			printf("Something is wrong. Connection was not found in queue.\n");
		}
	}
}



/* Uses the data that was fetched in recieve_whole_message and parses it into a Request */
void parse_received_msg(GString *received_message) {

	// parse received message // get inspirated by some protocols or httpd.c (maybe use headers, base64 for text, some delimiter for separating body, etc.)


	/*
	// truncate message body so only headers will left
	g_string_truncate(received_message, headers_length);

	// split message to headers
	gchar *start_of_headers = g_strstr_len(received_message->str, received_message->len, "\r\n");
	gchar **headers_arr = g_strsplit_set(start_of_headers, "\r\n", 0);

	// for each header line
	for (unsigned int i = 0; i < g_strv_length(headers_arr); i++) {

		// headers can also contains empty lines because "\r\n" are understood as two delimiters in split command
		if (strlen(headers_arr[i]) == 0)
			continue;

		gchar **header_line = g_strsplit_set(headers_arr[i], ":", 2);
		if (g_strv_length(header_line) != 2) {
			printf("WRONG FORMAT OF HEADER\n");
			g_strfreev(headers_arr);
			g_strfreev(header_line);
			return false;
		}

		gchar *header_name = g_ascii_strdown(header_line[0], -1); // convert to lowercase (arg. -1 if string is NULL terminated)
		gchar *header_value = g_strdup(header_line[1]);
		g_strstrip(header_value); // strip leading and trailing whitespaces
		g_strfreev(header_line); // free splitted line

		g_hash_table_insert(request->headers, header_name, header_value);
		// gchar *value = g_hash_table_lookup(hash_table, "key")
		// g_free(gchar *pointer);

		if (g_strcmp0(header_name, "host") == 0) {
			g_string_assign(request->host, header_value);
		}
		if (g_strcmp0(header_name, "connection") == 0) {
			if (g_strcmp0(header_value, "close") == 0)
				request->connection_close = true;
			if (!default_persistent && g_strcmp0(header_value, "keep-alive") != 0)
				request->connection_close = true;
		}
	}
	g_strfreev(headers_arr);

	*/

}


bool try_perform_ssl_handshake (ClientConnection *connection) {

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


GString* build_packet(int opcode, char *message)
{
	GString *packet = g_string_sized_new(MAX_PACKET_SIZE);

	// write opcode in binary form at the start of the packet
	g_string_append_len(packet, (char *)(&opcode), sizeof(int));
	g_string_append(packet, message);

	return packet;
}



/* Processes the request of client and builds a response,
   using recieve_whole_message, parse_request, create_html_page and log_msg */
void handle_connection(ClientConnection *connection) {

	g_timer_start(connection->conn_timer); // reset timer
	GString *response;

	// if SSL handshake was not performed yet
	if (!connection->ssl_handshake_done) {
		if (try_perform_ssl_handshake(connection)) {
			response = build_packet(INFO, "Welcome");
			write_message(connection, response->str, response->len);
			g_string_free(response, TRUE);
		}
		return;
	}

	// Receiving packet from socket
	GString *received_message = g_string_sized_new(MAX_PACKET_SIZE);
	if (!read_message(connection->ssl, received_message)) {
		// message was not received or has length 0
		remove_ClientConnection(connection);
		return;
	}
	//printf("Received:\n%s\n", received_message->str);

	// parse message from client
	parse_received_msg(received_message);

	g_string_append(response, "Encrypted greetings from server :)");

	write_message(connection, response->str, response->len);

	g_string_free(received_message, TRUE);

	printf("\n"); // empty line

	return;
}



/* check if socket is in the set of waiting sockets and handle connection if it is */
void handle_socket_if_waiting(ClientConnection *connection, fd_set *readfds) {

	if (FD_ISSET(connection->conn_fd, readfds)) {
		handle_connection(connection);
	}
}


/* check if there is a socket ready for writing and send write_buffer to client */
void send_message_if_ready(ClientConnection *connection, fd_set *writefds) {

	if (FD_ISSET(connection->conn_fd, writefds)) {
		write_message(connection, connection->write_buffer->str, connection->write_buffer->len);
	}
}


/* A looping function that waits for incoming connection, adds it
   to the queue and attempts to processes all clients waiting in the queue */
void run_loop() {
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

			log_msg(new_client, "New connection");

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


int main(int argc, char **argv)
{
	errno = 0; // reset

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
