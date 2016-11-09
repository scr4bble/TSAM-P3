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
#include <stdbool.h>

#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#include "getpasswd.h"


// useful macros
#ifndef max
	#define max(a,b) (((a) > (b)) ? (a) : (b))
	#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif


#define MAX_PASSWD_LENGTH 48

#define CA_CERT "../server.crt"


/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */

static const char CA_LOCATION[] = "";

static int socket_fd;
static SSL_CTX *ssl_ctx;
static SSL *ssl;
static int exitfd[2]; // [0] = read, [1] = write


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
			printf("Server closed connection.\n");
			return false;
		}
		buffer[n] = '\0';
		g_string_append_len(message, buffer, n);
	} while(n > 0 && n == BUFFER_SIZE - 1);

	return true;
}



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
		char *chatroom = strdup(&(line[i]));

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
		char passwd[MAX_PASSWD_LENGTH + 1];
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


	ssl = SSL_new(ssl_ctx);

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

	int ret = SSL_connect(ssl);
	if (ret == 1) {
		// SSL handshake was successful
		printf("handshake successful\n");
	}
	else {
		// SSL handshake was not successful, try to figure out what did happen
		int error = SSL_get_error(ssl, ret);
		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
			// operation did not complete the action, should be called again
			return;
		}
		else if (error == SSL_ERROR_SYSCALL) {
			printf("SSL_ERROR_SYSCALL\n");
			perror("");
		} else {
			printf("ret_val_connect: %d\n", ret);
			printf("error: %d\n", error);
			return;
		}
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
		struct timeval timeout;

		/* You must change this. Keep exitfd[0] in the read set to
		   receive the message from the signal handler. Otherwise,
		   the chat client can break in terrible ways. */
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(exitfd[0], &rfds);
		max_fd = max(STDIN_FILENO, exitfd[0]);
		FD_SET(socket_fd, &rfds);
		max_fd = max(socket_fd, max_fd);

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		int r = select(max_fd + 1, &rfds, NULL, NULL, &timeout);
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
			write(STDOUT_FILENO, "No message?\n", 12);
			fsync(STDOUT_FILENO);
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
				break;
			}
		}
		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			rl_callback_read_char();
		}

		/* Handle messages from the server here! */
		GString *received_message = g_string_sized_new(1024);
		if (!receive_whole_message(socket_fd, received_message)) {
			// message was not received or has length 0
			break;
		}
		else {
			printf("Received:\n%s\n", received_message->str);
		}
		g_string_free(received_message, TRUE);
	}

	/* replace by code to shutdown the connection and exit
	   the program. */
	clean_and_die(0);
}
