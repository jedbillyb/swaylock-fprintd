// Regression test for the crash that left sway showing an abandoned (red)
// lock: calling loop_remove_fd() from inside a dispatch callback used to free
// the list node that loop_poll()'s non-_safe wl_list_for_each was standing on,
// so the next iteration dereferenced freed memory (segfault at 8).
//
// This reproduces the exact shape of comm_in()/fp_comm_in() removing their own
// fd after a successful auth, while another fd is still registered behind them
// in the list.
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "loop.h"

static struct loop *loop;
static int fd_a[2], fd_b[2], fd_c[2];
static int calls_a, calls_b, calls_c;

static void cb_a(int fd, short mask, void *data) {
	calls_a++;
	// Remove ourselves from inside the callback -- the crashing pattern.
	loop_remove_fd(loop, fd);
}

static void cb_b(int fd, short mask, void *data) {
	calls_b++;
	char buf[8];
	read(fd, buf, sizeof(buf));
}

static void cb_c(int fd, short mask, void *data) {
	calls_c++;
	char buf[8];
	read(fd, buf, sizeof(buf));
}

int main(void) {
	loop = loop_create();

	if (pipe(fd_a) || pipe(fd_b) || pipe(fd_c)) {
		fprintf(stderr, "pipe failed\n");
		return 1;
	}

	// A is registered first so its removal happens while B and C are still
	// ahead of the iterator -- this is what corrupted the walk.
	loop_add_fd(loop, fd_a[0], POLLIN, cb_a, NULL);
	loop_add_fd(loop, fd_b[0], POLLIN, cb_b, NULL);
	loop_add_fd(loop, fd_c[0], POLLIN, cb_c, NULL);

	// Make all three readable in the same poll wakeup.
	write(fd_a[1], "x", 1);
	write(fd_b[1], "x", 1);
	write(fd_c[1], "x", 1);

	loop_poll(loop);

	if (calls_a != 1 || calls_b != 1 || calls_c != 1) {
		fprintf(stderr, "FAIL: first dispatch a=%d b=%d c=%d (want 1 1 1)\n",
			calls_a, calls_b, calls_c);
		return 1;
	}

	// A was removed. B and C must still work, and A must never fire again
	// even though its pipe still holds unread data.
	write(fd_b[1], "y", 1);
	write(fd_c[1], "y", 1);
	loop_poll(loop);

	if (calls_a != 1) {
		fprintf(stderr, "FAIL: removed fd fired again (a=%d)\n", calls_a);
		return 1;
	}
	if (calls_b != 2 || calls_c != 2) {
		fprintf(stderr, "FAIL: survivors broken b=%d c=%d (want 2 2)\n",
			calls_b, calls_c);
		return 1;
	}

	// Removing an fd outside a callback must still work.
	loop_remove_fd(loop, fd_b[0]);
	write(fd_c[1], "z", 1);
	loop_poll(loop);

	if (calls_b != 2) {
		fprintf(stderr, "FAIL: fd removed outside callback fired (b=%d)\n",
			calls_b);
		return 1;
	}
	if (calls_c != 3) {
		fprintf(stderr, "FAIL: c stopped dispatching (c=%d, want 3)\n", calls_c);
		return 1;
	}

	printf("PASS: remove-from-callback is safe; survivors keep dispatching\n");
	return 0;
}
