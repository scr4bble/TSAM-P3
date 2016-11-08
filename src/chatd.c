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
#include <stdbool.h>

#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>



// useful macros
#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

// default keep-alive timeout for clients
#define KEEP_ALIVE_TIMEOUT 30

// welcome message
static const char WELCOME_MSG[] = "Welcome";

static int sockfd; // master socket (server listening socket)
static GQueue *clients_queue;
//static GHashTable* cookies;


typedef struct ClientConnection {
	int conn_fd;
	GTimer *conn_timer;
	int request_count;
	struct sockaddr_in client_sockaddr;
	GString *cookie_token;
} ClientConnection;


/* Destroy/close/free instance of ClientConnection.
   @connection has to be allocated by malloc() */
void destroy_ClientConnection(ClientConnection *connection) {

	printf("Closing connection %s:%d (fd:%d)\n", inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), connection->conn_fd);

	close(connection->conn_fd); // close socket with client connection
	g_timer_destroy(connection->conn_timer); // destroy timer
	g_string_free(connection->cookie_token, TRUE);
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

	//fclose(log_file);

	printf("Closing %d connections.\n", clients_queue->length);

	destroy_clients_queue(clients_queue);
	clients_queue = NULL;

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



// TODO - need to be modified according to assignment !!!!!
/* Function for printing log messages to output. */
/*
void log_msg(Request *request) {

	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char iso_8601[] = "YYYY-MM-DDThh:mm:ssTZD";
	strftime(iso_8601, sizeof iso_8601, "%FT%T%Z", now_tm);


	GString *log_msg = g_string_new(iso_8601);
	g_string_append_printf(log_msg, " : %s %s %s : InsertResponseCodeHere \n", request->host->str, http_methods[request->method], request->path->str);

	fprintf(log_file, "%s", log_msg->str); // print log message to log file
	fflush(log_file);
	g_string_free(log_msg, TRUE); // free memory

	return;
}
*/



/* When a new client wishes to establish a connection, we create the connection and add it to the queue */
void new_client(int conn_fd) {
	ClientConnection *connection = g_new0(ClientConnection, 1);
	// find out client IP and port
	int addrlen = sizeof(connection->client_sockaddr);
	getpeername(conn_fd, (struct sockaddr*)&(connection->client_sockaddr), (socklen_t*)&addrlen);

	connection->conn_fd = conn_fd;
	connection->request_count = 0;
	connection->conn_timer = g_timer_new();
	connection->cookie_token = g_string_new(NULL);
	g_queue_push_tail(clients_queue, connection);
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


// TODO - need to be modified according to assignment !!!
/* Check timer of the connection and close/destroy connection if time exceeded KEEP_ALIVE_TIMEOUT seconds */
/*
void check_timer(ClientConnection *connection) {

	gdouble seconds_elapsed = g_timer_elapsed(connection->conn_timer, NULL);

	if (seconds_elapsed >= KEEP_ALIVE_TIMEOUT) {
		printf("[TIMEOUT] ");
		destroy_ClientConnection(connection);
		if (!g_queue_remove(clients_queue, connection)) {
			printf("Something is wrong. Connection was not found in queue.\n");
		}
	}
}*/


/* Receive whole packet from socket.
   Store data into @message (actual content of message will be discarded) */
bool receive_whole_message(int conn_fd, GString *message) {

	const ssize_t BUFFER_SIZE = 1024;
	ssize_t n = 0;
	char buffer[BUFFER_SIZE];
	g_string_truncate (message, 0); // empty provided GString variable

	do {
		n = recv(conn_fd, buffer, BUFFER_SIZE - 1, 0);
		if (n == -1) { // error while recv()
			perror("recv error");
		}
		else if (n == 0) {
			printf("Client was disconnected.\n");
			return false;
		}
		buffer[n] = '\0';
		g_string_append_len(message, buffer, n);
	} while(n > 0 && n == BUFFER_SIZE - 1);

	return true;
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


/* Processes the request of client and builds a response,
   using recieve_whole_message, parse_request, create_html_page and log_msg */
void handle_connection(ClientConnection *connection) {


	GString *response = g_string_sized_new(1024);


	// print out client IP and port
	printf("Serving client %s:%d (fd:%d)\n", inet_ntoa(connection->client_sockaddr.sin_addr),
			ntohs(connection->client_sockaddr.sin_port), connection->conn_fd);

	// Receiving packet from socket
	GString *received_message = g_string_sized_new(1024);
	if (!receive_whole_message(connection->conn_fd, received_message)) {
		// message was not received or has length 0
	}
	fprintf(stdout, "Received:\n%s\n", received_message->str);

	// parse request
	parse_received_msg(received_message);

	send(connection->conn_fd, response->str, response->len, 0);

	g_string_free(received_message, TRUE);
	g_string_free(response, TRUE);
	printf("\n"); // empty line

	return;
}



/* check if socket is in the set of waiting sockets and handle connection if it is */
void handle_socket_if_waiting(ClientConnection *connection, fd_set *readfds) {

	if (FD_ISSET(connection->conn_fd, readfds)) {
		handle_connection(connection);
	}
}

/* A looping function that waits for incoming connection, adds it
   to the queue and attempts to processes all clients waiting in the queue */
void run_loop() {
	struct sockaddr_in client;
	int max_sockfd;

	//cookies = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	fd_set readfds;
	while(42) {
		struct timeval tv;
		// every second check all timers - for purposes of handling keep-alive timeout
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		//clear the socket set
		FD_ZERO(&readfds);

		//add master socket to set
		FD_SET(sockfd, &readfds);
		max_sockfd = max(sockfd, return_max_sockfd_in_queue(clients_queue));

		//add child sockets to set
		g_queue_foreach(clients_queue, (GFunc) add_socket_into_set, &readfds);

		int retval = select(max_sockfd + 1, &readfds, NULL, NULL, &tv);
		if (retval < 0) {
			perror("select error");
			return;

		}
		else if (retval == 0) { // timeout
			// TODO: timeouts !!!
			//g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);
			continue;
		}

		if (FD_ISSET(sockfd, &readfds)) {
			//If something happened on the master socket , then its an incoming connection
			socklen_t len = (socklen_t) sizeof(client);
			// accept new client
			int conn_fd = accept(sockfd, (struct sockaddr *) &client, &len);

			//add new client into the queue
			new_client(conn_fd);

			printf("New connection: %s:%d (socket: %d )\n",
					inet_ntoa(client.sin_addr), ntohs(client.sin_port), conn_fd);

			handle_connection(g_queue_peek_tail(clients_queue));
		}

		g_queue_foreach(clients_queue, (GFunc) handle_socket_if_waiting, &readfds);

		// TODO - timers
		// check timer of every connection in queue
		//g_queue_foreach(clients_queue, (GFunc) check_timer, NULL);

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


bool start_listening(int server_port)
{
	struct sockaddr_in server;

	/* Create and bind a TCP socket */
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == 0) {
		perror("socket() failed");
		return false;
	}

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

	// create socket and start listening
	if (!start_listening(server_port)) {
		clean_and_die(1);
	}

	run_loop();

	clean_and_die(0);

	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());



	/* Receive and handle messages. */

	exit(EXIT_SUCCESS);
}
