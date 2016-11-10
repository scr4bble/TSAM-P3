#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h> // inet_addr()
#include <netdb.h> // gethostbyname()
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#include "getpasswd.h"
#include "chat_common.h"

// useful macros
#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif


#define CA_CERT "../server.crt"


//==================================================
/**********************
 ** GLOBAL VARIABLES **
 **********************/

/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
static int exitfd[2]; // [0] = read, [1] = write

static int socket_fd;
static SSL_CTX *ssl_ctx;
static SSL *ssl;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;
//==================================================


/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. The
   signal number is sent through a self pipe to notify the main loop
   of the received signal. This avoids a race condition in select. */
void
signal_handler(int signum)
{
	int _errno = errno;
	if (write(exitfd[1], &signum, sizeof(signum)) == -1 && errno != EAGAIN) {
		abort();
	}
	fsync(exitfd[1]);
	errno = _errno;
}

/* Closes the connection of both socket and file writer, runs destroy_clients_queue function and exits program */
void clean_and_die(int exit_code) {

	/* Close the connections. */
	// http://stackoverflow.com/questions/4160347/close-vs-shutdown-socket
	shutdown(socket_fd, SHUT_RDWR);
	close(socket_fd);

	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);
	EVP_cleanup();

	close(exitfd[0]);
	close(exitfd[1]);

	if (prompt)
		free(prompt);
	if (chatroom)
		free(chatroom);
	if (user)
		free(user);

	rl_callback_handler_remove();

	exit(exit_code);
}


static void initialize_exitfd(void)
{
	/* Establish the self pipe for signal handling. */
	if (pipe(exitfd) == -1) {
		perror("pipe()");
		exit(EXIT_FAILURE);
	}

	/* Make read and write ends of pipe nonblocking */
	int flags;
	flags = fcntl(exitfd[0], F_GETFL);
	if (flags == -1) {
		perror("fcntl-F_GETFL");
		exit(EXIT_FAILURE);
	}
	flags |= O_NONBLOCK;                /* Make read end nonblocking */
	if (fcntl(exitfd[0], F_SETFL, flags) == -1) {
		perror("fcntl-F_SETFL");
		exit(EXIT_FAILURE);
	}

	flags = fcntl(exitfd[1], F_GETFL);
	if (flags == -1) {
		perror("fcntl-F_SETFL");
		exit(EXIT_FAILURE);
	}
	flags |= O_NONBLOCK;                /* Make write end nonblocking */
	if (fcntl(exitfd[1], F_SETFL, flags) == -1) {
		perror("fcntl-F_SETFL");
		exit(EXIT_FAILURE);
	}

	/* Set the signal handler. */
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;           /* Restart interrupted reads()s */
	sa.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}



/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
	char buffer[256];
	if (NULL == line) {
		rl_callback_handler_remove();
		signal_handler(SIGTERM);
		return;
	}
	if (strlen(line) > 0) {
		add_history(line);
	}
	if ((strncmp("/bye", line, 4) == 0) || (strncmp("/quit", line, 5) == 0)) {
		rl_callback_handler_remove();
		signal_handler(SIGTERM);
		return;
	}
	if (strncmp("/game", line, 5) == 0) {
		/* Skip whitespace */
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
			write(STDOUT_FILENO, "Usage: /game username\n",
				  29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		/* Start game */
		return;
	}
	if (strncmp("/join", line, 5) == 0) {
		int i = 5;
		/* Skip whitespace */
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
			write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		//char *chatroom = strdup(&(line[i])); // chat room will be set up after confirmation from server

		/* Process and send this information to the server. */

		/* Maybe update the prompt. */
		free(prompt);
		prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
		return;
	}
	if (strncmp("/list", line, 5) == 0) {
			/* Query all available chat rooms */
			return;
	}
	if (strncmp("/roll", line, 5) == 0) {
			/* roll dice and declare winner. */
			return;
	}
	if (strncmp("/say", line, 4) == 0) {
		/* Skip whitespace */
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
				write(STDOUT_FILENO, "Usage: /say username message\n",
					  29);
				fsync(STDOUT_FILENO);
				rl_redisplay();
				return;
		}
		/* Skip whitespace */
		int j = i+1;
		while (line[j] != '\0' && isgraph(line[j])) { j++; }
		if (line[j] == '\0') {
				write(STDOUT_FILENO, "Usage: /say username message\n",
					  29);
				fsync(STDOUT_FILENO);
				rl_redisplay();
				return;
		}
		char *receiver = strndup(&(line[i]), j - i - 1);
		char *message = strndup(&(line[j]), j - i - 1);

		/* Send private message to receiver. */

		return;
	}
	if (strncmp("/user", line, 5) == 0) {
		int i = 5;
		/* Skip whitespace */
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
				write(STDOUT_FILENO, "Usage: /user username\n", 22);
				fsync(STDOUT_FILENO);
				rl_redisplay();
				return;
		}
		char *new_user = strdup(&(line[i]));
		char passwd[MAX_PASSWORD_LENGTH + 1];
		getpasswd("Please enter password: ", passwd, sizeof(passwd));

		/* Process and send this information to the server. */
		printf("Do something with the password <<%s>>\n", passwd);

		/* Maybe update the prompt. */
		free(prompt);
		prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
		return;
	}
	if (strncmp("/who", line, 4) == 0) {
		/* Query all available users */
		return;
	}
	/* Sent the buffer to the server. */
	snprintf(buffer, 255, "Message: %s\n", line);
	write(STDOUT_FILENO, buffer, strlen(buffer));
	fsync(STDOUT_FILENO);
}


void print_message(int msg_type, char *sender, char *message)
{
	char *color_of_message = ANSI_COLOR_RESET;

	switch(msg_type) {
		case CLIENT_ERROR:
		case ERROR:
			color_of_message = ANSI_COLOR_RED;
			break;
		case INFO:
		case CHANGE_ROOM:
		case LOGGED_IN:
			color_of_message = ANSI_COLOR_GREEN;
			break;
		case ROOM_MESSAGE:
			break;
		case PRIVATE_MESSAGE:
			color_of_message = ANSI_COLOR_MAGENTA;
			break;
		case CHALLENGE:
			color_of_message = ANSI_COLOR_CYAN;
			break;
		default:
			break;
	}

	time_t now = time(NULL);
	struct tm *now_tm = gmtime(&now);
	char timestamp[] = "hh:mm:ss";
	strftime(timestamp, sizeof timestamp, "%T", now_tm);

	printf("\r[%s] ", timestamp);
	if (sender) {
		printf("<");
		print_colored(sender, color_of_message);
		printf("> ");
	}
	print_colored(message, ANSI_COLOR_RESET);
	printf("\n");
}


/* return false if server closed connection */
bool process_server_message()
{

	GString *received_packet = g_string_sized_new(1024);
	if (!read_message(ssl, received_packet)) {
		// connection was probably closed
		return false;
	}

	int opcode = *((int *)received_packet->str);
	char *message = received_packet->str + sizeof(int); // packet without opcode
	// message won't be larger than incoming packet was
	GString *output_message = g_string_sized_new(MAX_PACKET_SIZE);; // message what will be print to client's console
	GString *sender = g_string_sized_new(MAX_USERNAME_LENGTH);; // message what will be print to client's console

/*
	ERROR,            // for example - room does not exist, username does not exist, bad password, etc.
	CHANGE_ROOM,      // after receiving this message client can set up internal variable with room
	LOGGED_IN,        // after receiving this message client can set up internal variable with username
	MESSAGE,          // just print out message from server (room message) "<OPCODE><USERNAME> <MESSAGE>"
	PRIVATE_MESSAGE,  // private message (client should print that in different way from room messages) "<OPCODE><USERNAME> <MESSAGE>"
	CHALLENGE         // challenge from another user (game)
*/
	switch (opcode) {
		case ERROR:
			g_string_assign(sender, "SERVER");
			int error = *((int *)message);
			message = message + sizeof(int); // move pointer after error code
			if (error == WRONG_PASSWORD) {
				int num_of_tries = *((int *)message);
				g_string_printf(output_message, WRONG_PASSWORD_MSG, num_of_tries);
			} else if (error == WRONG_USERNAME) {
				int num_of_tries = *((int *)message);
				g_string_printf(output_message, WRONG_USERNAME_MSG, num_of_tries);
			}
			/*else if (error == ROOM_NOT_FOUND) {
				// not used, since user will create the room if it does not exist
				// name of room is in the message
				g_string_printf(output_message, error_message_[ROOM_NOT_FOUND], message);
			}*/
			else if (error == UNKNOWN)
				g_string_printf(output_message, UNKNOWN_ERROR_MSG);
			break;
		case INFO:
			g_string_assign(sender, "SERVER");
			g_string_assign(output_message, message);
			break;
		case CHANGE_ROOM:
			g_string_assign(sender, "SERVER");
			g_string_printf(output_message, "You have entered room [%s].", message);
			chatroom = strdup(message);
			break;
		case LOGGED_IN:
			g_string_assign(sender, "SERVER");
			g_string_printf(output_message, "Successfully logged in as [%s].", message);
			user = strdup(message);
			break;
		case ROOM_MESSAGE:
		case PRIVATE_MESSAGE:
			; // http://stackoverflow.com/questions/18496282/why-do-i-get-a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a
			gchar **msg = g_strsplit(message, " ", 2); // split into username and message
			if (g_strv_length(msg) == 2) {
				g_string_assign(sender, msg[0]);
				g_string_assign(output_message, msg[1]);
			}
			else
				printf("Corrupted packet !!\n");
			g_strfreev(msg);
			break;
		case CHALLENGE:
			g_string_printf(output_message, "You are challenged to Game of Fortune by [%s]. Use /accept or /decline to answer.", message);
			break;
	}
	print_message(opcode, sender->str, output_message->str);


	g_string_free(received_packet, TRUE);
	g_string_free(output_message, TRUE);
	g_string_free(sender, TRUE);
	return true;
}


bool initialize_openssl()
{
	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_client_method());

	if(!ssl_ctx) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	if (!SSL_CTX_load_verify_locations(ssl_ctx, CA_CERT, NULL)) {
		ERR_print_errors_fp(stderr);
		return false;
	}

	// setting up verification flags
	// SSL_VERIFY_NONE - no request for a certificate is sent to the client
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL); // NULL = built-in default verification function will be used
	/* Set the verification depth to 1 */
	SSL_CTX_set_verify_depth(ssl_ctx,1);

	// don't return from SSL_read()/SSL_write() until success or error (example case: renegotiation of SSL)
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

	ssl = SSL_new(ssl_ctx);
	SSL_set_connect_state(ssl);

	return true;
}

// returns socket_fd or -1 in case of error
int connect_server(const char *hostname, const int port)
{
	struct sockaddr_in server;

	/* Create and bind a TCP socket */
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd == 0) {
		perror("socket() failed");
		return -1;
	}

	const struct hostent* host_info = NULL;
	if ((host_info = gethostbyname(hostname)) == NULL) {  // get the host info
        herror("gethostbyname");
        return -1;
    }
	struct in_addr *ip_address = (struct in_addr *) host_info->h_addr_list[0];

	//printf("%s\n", inet_ntoa(*ip_address));

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = ip_address->s_addr;
	server.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr*) &server, sizeof(server)) != 0) {
		perror("connect() failed");
		return -1;
	}

	return sockfd;
}


int main(int argc, char **argv)
{
	errno = 0; // reset
	int max_fd = 0;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <address> <port>\n", argv[0]);
		return EXIT_FAILURE;
	}

	const char *ip_address = argv[1];
	const int server_port = strtol(argv[2], NULL, 10);

	// make pipe for redirecting signals to socket in the set used by select()
	// catch SIGINT & SIGTERM
	initialize_exitfd();

	/* Initialize OpenSSL */
	if (!initialize_openssl()) {
		return EXIT_FAILURE;
	}

	// connect to the chat server
	socket_fd = connect_server(ip_address, server_port);
	if (socket_fd < 0) {
		return EXIT_FAILURE;
	}

	/* Use the socket for the SSL connection. */
	SSL_set_fd(ssl, socket_fd);

	ERR_clear_error();
	int ret = SSL_connect(ssl);
	if (ret == 1) {
		// SSL handshake was successful
		printf("Connected to %s:%d\n", ip_address, server_port);
	} else {
		fprintf(stderr, "SSL handshake failed\n");
		clean_and_die(EXIT_FAILURE);
	}

	/* Now we can create BIOs and use them instead of the socket.
	 * The BIO is responsible for maintaining the state of the
	 * encrypted connection and the actual encryption. Reads and
	 * writes to sock_fd will insert unencrypted data into the
	 * stream, which even may crash the server.
	 */

	/* Set up secure connection to the chatd server. */

	/* Read characters from the keyboard while waiting for input.
	 */
	prompt = strdup("> ");
	rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
	for (;;) {
		fd_set rfds;
		//struct timeval timeout;

		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(exitfd[0], &rfds);
		max_fd = max(STDIN_FILENO, exitfd[0]);
		FD_SET(socket_fd, &rfds);
		max_fd = max(socket_fd, max_fd);

		//timeout.tv_sec = 5;
		//timeout.tv_usec = 0;

		int r = select(max_fd + 1, &rfds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR) {
				/* This should either retry the call or
				   exit the loop, depending on whether we
				   received a SIGTERM. */
				continue;
			}
			/* Not interrupted, maybe nothing we can do? */
			perror("select()");
			break;
		}
		if (r == 0) { // timeout
			// since timeout is not implemented, this should not happen

			//write(STDOUT_FILENO, "No message?\n", 12);
			//fsync(STDOUT_FILENO);
			/* Whenever you print out a message, call this
			   to reprint the current input line. */
			rl_redisplay();
			continue;
		}
		if (FD_ISSET(exitfd[0], &rfds)) {
			/* We received a signal. */
			int signum;
			for (;;) {
				if (read(exitfd[0], &signum, sizeof(signum)) == -1) {
					if (errno == EAGAIN) {
						break;
					} else {
						perror("read()");
						exit(EXIT_FAILURE);
					}
				}
			}
			if (signum == SIGINT || signum == SIGTERM) {
				/* Clean-up and exit. */
				printf("\nShutting down...\n");
				clean_and_die(0);
				break;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			rl_callback_read_char();
		}

		if (FD_ISSET(socket_fd, &rfds)) {
			/* Handle messages from the server here! */
			if (!process_server_message())
				clean_and_die(1);
		}
	}

	clean_and_die(0);
}
