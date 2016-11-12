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


#define CA_CERT "server.crt"


//==================================================
/**********************
 ** GLOBAL VARIABLES **
 **********************/

/* This variable holds a file descriptor of a pipe on which we send a
 * number if a signal is received. */
static int exitfd[2]; // [0] = read, [1] = write

// variable for buffering outcoming packets
// DON'T USE OUTSIDE build_and_send_packet() function !!!
static GString *packet;
static GString *temp_string;

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
static GString *prompt;
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

	if (chatroom)
		free(chatroom);
	if (user)
		free(user);

	rl_callback_handler_remove();

	g_string_free(prompt, true);
	g_string_free(packet, true);
	g_string_free(temp_string, true);

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


void update_prompt()
{
	// reset prompt
	g_string_truncate(prompt, 0);

	if (user) {
		g_string_append_printf(prompt, "(%s) ", user);
	}
	if (chatroom) {
		g_string_append_printf(prompt, "#%s ", chatroom);
	}

	g_string_append(prompt, "> ");

	rl_set_prompt(prompt->str);
}



/* Build packet and try to send it through encrypted ssl connection.
 * @len - how many bytes of @message will be dispatched
 */
void build_and_send_packet(int opcode, const char *message, int len)
{

	g_string_truncate(packet, 0);

	// write opcode in binary form at the start of the packet
	g_string_append_len(packet, (char *)(&opcode), sizeof(int));
	g_string_append(packet, message);

	ERR_clear_error();
	if (len <= 0) // if there are not doubts that message can fit into one packet
		len = packet->len;
	else
		len += sizeof(int); // adding size of opcode

	int n = SSL_write(ssl, packet->str, len);

	if (n <= 0) {
		// perror("SSL_write error");
		// probably closed connection
		rl_callback_handler_remove();
		signal_handler(SIGTERM);
	}

}

// Username can contain only \"A-Za-z0-9._-|\" and must be max. MAX_USERNAME_LENGTH characters long.
bool check_username(const char *username)
{
	int username_length = strlen(username);

	if (username_length > MAX_USERNAME_LENGTH)
		return false;

	for (int i = 0; i < username_length; ++i)
	{
		if ((username[i] < '0' || username[i] > '9') &&
			(username[i] < 'a' || username[i] > 'z') &&
			(username[i] < 'A' || username[i] > 'Z') &&
			(username[i] != '_') && (username[i] != '-') &&
			(username[i] != '.') && (username[i] != '|'))
			return false;
	}
	return true;
}


void print_message(int msg_type, char *sender, char *message)
{
	char *color = ANSI_COLOR_RESET;

	switch(msg_type) {
		case CLIENT_ERROR:
		case ERROR:
			color = ANSI_COLOR_RED;
			break;
		case INFO:
		case CHANGE_ROOM:
		case LOGGED_IN:
		case USER_CREATED:
			color = ANSI_COLOR_GREEN;
			break;
		case ROOM_MESSAGE:
			break;
		case PRIVATE_MESSAGE_SENT:
		case PRIVATE_MESSAGE_RECEIVED:
			color = ANSI_COLOR_MAGENTA;
			break;
		case CHALLENGE:
			color = ANSI_COLOR_CYAN;
			break;
		default:
			break;
	}

	time_t now = time(NULL);

	struct tm *now_tm = gmtime(&now);
	char timestamp[] = "hh:mm:ss";
	strftime(timestamp, sizeof timestamp, "%T", now_tm);

	g_string_printf(temp_string, "\r[%s] ", timestamp);
	print_colored(temp_string->str, ANSI_COLOR_CYAN);
	if (sender) {
		if (msg_type == PRIVATE_MESSAGE_SENT)
			printf("to ");
		printf("<");
		print_colored(sender, color);
		printf("> ");
	}
	print_colored(message, ANSI_COLOR_RESET);
	printf("\n");
	rl_forced_update_display();
}


void clear_line()
{
	rl_set_prompt("");
	rl_replace_line("", 0);
	rl_redisplay();
	update_prompt();
}


/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
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
		int i = 5;
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
			write(STDOUT_FILENO, "Usage: /game username\n",
				  29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		/* Start game */
		const char *username = &(line[i]);
		build_and_send_packet(GAME, username, strlen(username));
		return;
	}
	if (strncmp("/accept", line, 7) == 0) {
		/* Accept game */
		build_and_send_packet(ACCEPT, "", 0);
		return;
	}
	if (strncmp("/decline", line, 8) == 0) {
		/* Decline game */
		build_and_send_packet(DECLINE, "", 0);
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
		const char *room = &(line[i]);
		build_and_send_packet(JOIN, room, strlen(room));
		return;
	}
	if (strncmp("/list", line, 5) == 0) {
		/* Query all available chat rooms */
		build_and_send_packet(LIST, "", 0);
		return;
	}
	if (strncmp("/roll", line, 5) == 0) {
		/* roll dice and declare winner. */
		return;
	}
	if (strncmp("/say", line, 4) == 0) {
		/* Skip whitespaces and detect start of the username */
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) { i++; }
		if (line[i] == '\0') {
				write(STDOUT_FILENO, "Usage: /say username message\n",
					  29);
				fsync(STDOUT_FILENO);
				rl_redisplay();
				return;
		}
		int j = i;

		/* detect start of the message */
		while (line[j] != '\0' && isgraph(line[j])) { j++; }
		if (line[j] == '\0') {
				write(STDOUT_FILENO, "Usage: /say username message\n",
					  29);
				fsync(STDOUT_FILENO);
				rl_redisplay();
				return;
		}
		char *receiver = strndup(&(line[i]), j - i);
		/* Skip whitespaces */
		while (line[j] != '\0' && isspace(line[j])) { j++; }

		char *message = &(line[j]);

		/* Sent the message to the receiver splitted if necessary (MAX_MESSAGE_SIZE). */
		for (int msg_len = strlen(message); msg_len > MAX_MESSAGE_SIZE; msg_len -= MAX_MESSAGE_SIZE) {
			g_string_printf(temp_string, "%s %s", receiver, message);
			build_and_send_packet(SAY, temp_string->str, MAX_MESSAGE_SIZE + 1 + strlen(receiver));
			message += MAX_MESSAGE_SIZE;
		}
		g_string_printf(temp_string, "%s %s", receiver, message);
		build_and_send_packet(SAY, temp_string->str, strlen(message) + 1 + strlen(receiver));

		free(receiver);
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
		const char *new_user = &(line[i]);
		if (!check_username(new_user)) {
			char error_message[512];
			sprintf(error_message, "Username can contain only \"A-Za-z0-9._-|\" and must be max. %d characters long.", MAX_USERNAME_LENGTH);
			print_message(CLIENT_ERROR, "CLIENT", error_message);
			clear_line();
			return;
		}

		char passwd[MAX_PASSWORD_LENGTH + 1];
		getpasswd("Please enter password: ", passwd, sizeof(passwd));

		if (strlen(passwd) > MAX_PASSWORD_LENGTH) {
			char error_message[512];
			sprintf(error_message, "Password must be max. %d characters long.", MAX_PASSWORD_LENGTH);
			print_message(CLIENT_ERROR, "CLIENT", error_message);
			clear_line();
			return;
		}

		g_string_assign(temp_string, new_user);
		g_string_append_printf(temp_string, " %s", passwd);
		build_and_send_packet(USER, temp_string->str, temp_string->len);

		return;
	}
	if (strncmp("/who", line, 4) == 0) {
		/* Query all available users */
		build_and_send_packet(WHO, "", 0);
		return;
	}
	if (strncmp("/", line, 1) == 0) {
		print_message(CLIENT_ERROR, "CLIENT", "Unknown command.");
		clear_line();
		return;
	}
	/* Sent the buffer to the server. */
	// split line to more messages if necessary
	for (int msg_len = strlen(line); msg_len > MAX_MESSAGE_SIZE; msg_len -= MAX_MESSAGE_SIZE) {
		build_and_send_packet(MSG, line, MAX_MESSAGE_SIZE);
		line += MAX_MESSAGE_SIZE;
	}
	build_and_send_packet(MSG, line, strlen(line));
}



/* return false if server closed connection */
bool process_server_message()
{

	GString *received_packet = g_string_sized_new(1024);
	if (!recv_packet(ssl, received_packet)) {
		// connection was probably closed
		return false;
	}

	int opcode = *((int *)received_packet->str);
	char *message = received_packet->str + sizeof(int); // packet without opcode
	// message won't be larger than incoming packet was
	GString *output_message = g_string_sized_new(MAX_PACKET_SIZE); // message what will be print to client's console
	GString *sender = g_string_sized_new(MAX_USERNAME_LENGTH); // message what will be print to client's console

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
			g_string_assign(output_message, message);
			break;
		case INFO:
			g_string_assign(sender, "SERVER");
			g_string_assign(output_message, message);
			break;
		case CHANGE_ROOM:
			g_string_assign(sender, "SERVER");
			g_string_printf(output_message, "You have entered room [%s].", message);
			chatroom = strdup(message);
			update_prompt();
			break;
		case LOGGED_IN:
			g_string_assign(sender, "SERVER");
			g_string_assign(output_message, "Successfully logged in.");
			user = strdup(message);
			update_prompt();
			break;
		case USER_CREATED:
			g_string_assign(sender, "SERVER");
			g_string_assign(output_message, "Successfully logged in (new user created).");
			user = strdup(message);
			update_prompt();
			break;
		case ROOM_MESSAGE:
		case PRIVATE_MESSAGE_SENT:
		case PRIVATE_MESSAGE_RECEIVED:
			; // http://stackoverflow.com/questions/18496282/why-do-i-get-a-label-can-only-be-part-of-a-statement-and-a-declaration-is-not-a
			gchar **msg = g_strsplit(message, " ", 2); // split into username and message
			if (g_strv_length(msg) == 2) {
				g_string_assign(sender, msg[0]);
				g_string_assign(output_message, msg[1]);
			}
			else
				print_message(CLIENT_ERROR, "CLIENT", "Corrupted packet !!");
			g_strfreev(msg);
			break;
		case CHALLENGE:
			g_string_assign(sender, "SERVER");
			g_string_printf(output_message, "You have been challenged to Game of Fortune by user [%s]. Use /accept or /decline to answer.", message);
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


int main(int argc, char **argv) {
	errno = 0; // reset
	int max_fd = 0;
	prompt = g_string_new(NULL);
	// just initializing the variable for buffering outcoming packets
	packet = g_string_sized_new(MAX_PACKET_SIZE);
	temp_string = g_string_sized_new(MAX_PACKET_SIZE);

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

	/* Set up secure connection to the chatd server. */
	ERR_clear_error();
	int ret = SSL_connect(ssl);
	if (ret == 1) {
		// SSL handshake was successful
		printf("Connected to %s:%d\n", ip_address, server_port);
	} else {
		fprintf(stderr, "SSL handshake failed\n");
		clean_and_die(EXIT_FAILURE);
	}


	update_prompt();
	rl_callback_handler_install(prompt->str, (rl_vcpfunc_t*) &readline_callback);
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
