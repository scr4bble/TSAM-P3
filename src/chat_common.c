#include "chat_common.h"

/* Receive whole packet from socket.
   Store decrypted data into @message (actual content of message will be discarded) */
bool read_message(SSL *ssl, GString *message) {

	const ssize_t BUFFER_SIZE = 1024;
	ssize_t n = 0;
	char buffer[BUFFER_SIZE];
	g_string_truncate (message, 0); // empty provided GString variable

	ERR_clear_error();
	n = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
	int error = SSL_get_error(ssl, n);

	switch (error) {
		case SSL_ERROR_NONE:
			buffer[n] = '\0'; // just in case, not needed
			g_string_append_len(message, buffer, n);
			break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			return true;
		default:
			// perror("SSL_read error");
			// closed connection ???
			return false;
	}

	return true;
}
