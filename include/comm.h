#ifndef _SWAYLOCK_COMM_H
#define _SWAYLOCK_COMM_H

#include <stdbool.h>

struct swaylock_password;

bool spawn_comm_child(void);
ssize_t read_comm_request(char **buf_ptr);
bool write_comm_reply(bool success);
// Requests the provided password to be checked. The password is always cleared
// when the function returns.
bool write_comm_request(struct swaylock_password *pw);
bool read_comm_reply(bool *auth_success);
// FD to poll for password authentication replies.
int get_comm_reply_fd(void);

// Fingerprint backend (PAM only). The fingerprint child runs an independent,
// permanent verify loop so it never blocks password entry.
//
// Parent: tell the fingerprint child to begin its verify loop. Called once,
// after argument parsing, only when --fingerprint is enabled.
void start_fingerprint(void);
// Child: block until the parent calls start_fingerprint(). Returns false on
// EOF (parent gone / fingerprint never enabled), in which case the child exits.
bool wait_fp_start(void);
// Child: write a single fingerprint result to the parent.
bool write_fp_reply(bool success);
// Parent: read a single fingerprint result. Returns false if the child is gone.
bool read_fp_reply(bool *auth_success);
// Parent: FD to poll for fingerprint authentication replies.
int get_fp_reply_fd(void);
// Parent: kill the auth children on shutdown so the fingerprint child releases
// its claim on the reader. Safe to call more than once.
void terminate_comm_children(void);

#endif
