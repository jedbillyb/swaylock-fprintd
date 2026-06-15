#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "comm.h"
#include "config.h"
#include "log.h"
#include "swaylock.h"
#include "password-buffer.h"

static int comm[2][2] = {{-1, -1}, {-1, -1}};
// Fingerprint child pipes: [0] = start/control (parent -> child),
// [1] = reply (child -> parent).
static int fp_comm[2][2] = {{-1, -1}, {-1, -1}};
static pid_t pw_child_pid = -1;
static pid_t fp_child_pid = -1;

static ssize_t read_full(int fd, void *dst, size_t size) {
	char *buf = dst;
	size_t offset = 0;
	while (offset < size) {
		ssize_t n = read(fd, &buf[offset], size - offset);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			swaylock_log_errno(LOG_ERROR, "read() failed");
			return -1;
		} else if (n == 0) {
			if (offset == 0) {
				return 0;
			}
			swaylock_log(LOG_ERROR, "read() failed: unexpected EOF");
			return -1;
		}
		offset += n;
	}
	return offset;
}

static bool write_full(int fd, const void *src, size_t size) {
	const char *buf = src;
	size_t offset = 0;
	while (offset < size) {
		ssize_t n = write(fd, &buf[offset], size - offset);
		if (n <= 0) {
			assert(n != 0);
			if (errno == EINTR) {
				continue;
			}
			swaylock_log_errno(LOG_ERROR, "write() failed");
			return false;
		}
		offset += n;
	}
	return true;
}

ssize_t read_comm_request(char **buf_ptr) {
	int fd = comm[0][0];

	size_t size;
	ssize_t n = read_full(fd, &size, sizeof(size));
	if (n <= 0) {
		return n;
	}
	assert(size > 0);

	swaylock_log(LOG_DEBUG, "received pw check request");

	char *buf = password_buffer_create(size);
	if (!buf) {
		return -1;
	}

	if (read_full(fd, buf, size) <= 0) {
		swaylock_log_errno(LOG_ERROR, "failed to read pw");
		return -1;
	}

	assert(buf[size - 1] == '\0');
	*buf_ptr = buf;
	return size;
}

bool write_comm_reply(bool success) {
	return write_full(comm[1][1], &success, sizeof(success));
}

bool spawn_comm_child(void) {
	if (pipe(comm[0]) != 0) {
		swaylock_log_errno(LOG_ERROR, "failed to create pipe");
		return false;
	}
	if (pipe(comm[1]) != 0) {
		swaylock_log_errno(LOG_ERROR, "failed to create pipe");
		return false;
	}
#if HAVE_PAM
	if (pipe(fp_comm[0]) != 0 || pipe(fp_comm[1]) != 0) {
		swaylock_log_errno(LOG_ERROR, "failed to create fingerprint pipe");
		return false;
	}
#endif

	pid_t child = fork();
	if (child < 0) {
		swaylock_log_errno(LOG_ERROR, "failed to fork");
		return false;
	} else if (child == 0) {
		struct sigaction sa = {
			.sa_handler = SIG_IGN,
		};
		sigaction(SIGUSR1, &sa, NULL);
		close(comm[0][1]);
		close(comm[1][0]);
#if HAVE_PAM
		// The password child does not use the fingerprint pipes.
		close(fp_comm[0][0]);
		close(fp_comm[0][1]);
		close(fp_comm[1][0]);
		close(fp_comm[1][1]);
#endif
		run_pw_backend_child();
	}
	pw_child_pid = child;

#if HAVE_PAM
	pid_t fp_child = fork();
	if (fp_child < 0) {
		swaylock_log_errno(LOG_ERROR, "failed to fork fingerprint child");
		return false;
	} else if (fp_child == 0) {
		struct sigaction sa = {
			.sa_handler = SIG_IGN,
		};
		sigaction(SIGUSR1, &sa, NULL);
		// The fingerprint child does not use the password pipes.
		close(comm[0][0]);
		close(comm[0][1]);
		close(comm[1][0]);
		close(comm[1][1]);
		close(fp_comm[0][1]); // parent's write end of the control pipe
		close(fp_comm[1][0]); // parent's read end of the reply pipe
		run_fp_backend_child();
	}
	fp_child_pid = fp_child;
#endif

	close(comm[0][0]);
	close(comm[1][1]);
#if HAVE_PAM
	close(fp_comm[0][0]); // child's read end of the control pipe
	close(fp_comm[1][1]); // child's write end of the reply pipe
#endif
	return true;
}

void start_fingerprint(void) {
	if (fp_comm[0][1] < 0) {
		return;
	}
	char c = 1;
	if (!write_full(fp_comm[0][1], &c, sizeof(c))) {
		swaylock_log(LOG_ERROR, "failed to start the fingerprint child");
	}
}

bool wait_fp_start(void) {
	char c;
	return read_full(fp_comm[0][0], &c, sizeof(c)) > 0;
}

bool write_fp_reply(bool success) {
	return write_full(fp_comm[1][1], &success, sizeof(success));
}

bool read_fp_reply(bool *auth_success) {
	return read_full(fp_comm[1][0], auth_success, sizeof(*auth_success)) > 0;
}

int get_fp_reply_fd(void) {
	return fp_comm[1][0];
}

void terminate_comm_children(void) {
	if (fp_child_pid > 0) {
		// SIGKILL drops the child's D-Bus connection, which makes fprintd
		// release its claim on the reader.
		kill(fp_child_pid, SIGKILL);
		fp_child_pid = -1;
	}
	// The password child exits on its own once its request pipe is closed.
}

bool write_comm_request(struct swaylock_password *pw) {
	bool result = false;
	int fd = comm[0][1];

	size_t size = pw->len + 1;
	if (!write_full(fd, &size, sizeof(size))) {
		swaylock_log_errno(LOG_ERROR, "Failed to write pw size");
		goto out;
	}

	if (!write_full(fd, pw->buffer, size)) {
		swaylock_log_errno(LOG_ERROR, "Failed to write pw buffer");
		goto out;
	}

	result = true;

out:
	clear_password_buffer(pw);
	return result;
}

bool read_comm_reply(bool *auth_success) {
	if (read_full(comm[1][0], auth_success, sizeof(*auth_success)) <= 0) {
		swaylock_log(LOG_ERROR, "Failed to read pw result");
		return false;
	}
	return true;
}

int get_comm_reply_fd(void) {
	return comm[1][0];
}
