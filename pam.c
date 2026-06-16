#define _POSIX_C_SOURCE 200809L
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "comm.h"
#include "log.h"
#include "password-buffer.h"
#include "swaylock.h"

void initialize_pw_backend(int argc, char **argv) {
	if (getuid() != geteuid() || getgid() != getegid()) {
		swaylock_log(LOG_ERROR,
			"swaylock is setuid, but was compiled with the PAM"
			" backend. Run 'chmod a-s %s' to fix. Aborting.", argv[0]);
		exit(EXIT_FAILURE);
	}
	if (!spawn_comm_child()) {
		exit(EXIT_FAILURE);
	}
}

struct conv_state {
	char *password;
};

static int handle_conversation(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *data) {
	struct conv_state *state = data;

	/* PAM expects an array of responses, one for each message */
	struct pam_response *pam_reply =
		calloc(num_msg, sizeof(struct pam_response));
	if (pam_reply == NULL) {
		swaylock_log(LOG_ERROR, "Allocation failed");
		return PAM_ABORT;
	}
	*resp = pam_reply;
	for (int i = 0; i < num_msg; ++i) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			/* workaround pam_systemd_home internal retries:
			 * https://github.com/systemd/systemd/blob/main/src/home/pam_systemd_home.c#L594-L599
			 * if the password has already been rejected once, abort the conversation */
			if (state->password == NULL) {
				return PAM_ABORT;
			}
			pam_reply[i].resp = strdup(state->password); // PAM clears and frees this
			if (pam_reply[i].resp == NULL) {
				swaylock_log(LOG_ERROR, "Allocation failed");
				return PAM_ABORT;
			}
			state->password = NULL;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			break;
		}
	}
	return PAM_SUCCESS;
}

static const char *get_pam_auth_error(int pam_status) {
	switch (pam_status) {
	case PAM_AUTH_ERR:
		return "invalid credentials";
	case PAM_CRED_INSUFFICIENT:
		return "swaylock cannot authenticate users; check /etc/pam.d/swaylock "
			"has been installed properly";
	case PAM_AUTHINFO_UNAVAIL:
		return "authentication information unavailable";
	case PAM_MAXTRIES:
		return "maximum number of authentication tries exceeded";
	default:;
		static char msg[64];
		snprintf(msg, sizeof(msg), "unknown error (%d)", pam_status);
		return msg;
	}
}

void run_pw_backend_child(void) {
	char *pw_buf = NULL;
	struct passwd *passwd = getpwuid(getuid());
	if (!passwd) {
		swaylock_log_errno(LOG_ERROR, "getpwuid failed");
		exit(EXIT_FAILURE);
	}

	char *username = passwd->pw_name;

	struct conv_state state = {0};
	const struct pam_conv conv = {
		.conv = handle_conversation,
		.appdata_ptr = &state,
	};
	pam_handle_t *auth_handle = NULL;
	if (pam_start("swaylock", username, &conv, &auth_handle) != PAM_SUCCESS) {
		swaylock_log(LOG_ERROR, "pam_start failed");
		exit(EXIT_FAILURE);
	}

	/* This code does not run as root */
	swaylock_log(LOG_DEBUG, "Prepared to authorize user %s", username);

	int pam_status = PAM_SUCCESS;
	while (1) {
		ssize_t size = read_comm_request(&pw_buf);
		if (size < 0) {
			exit(EXIT_FAILURE);
		} else if (size == 0) {
			break;
		}

		state.password = pw_buf;
		int pam_status = pam_authenticate(auth_handle, 0);
		password_buffer_destroy(pw_buf, size);
		pw_buf = NULL;
		state.password = NULL;

		bool success = pam_status == PAM_SUCCESS;
		if (!success) {
			swaylock_log(LOG_ERROR, "pam_authenticate failed: %s",
				get_pam_auth_error(pam_status));
		}

		if (!write_comm_reply(success)) {
			exit(EXIT_FAILURE);
		}

		if (success) {
			/* Unsuccessful requests may be queued after a successful one;
			 * do not process them. */
			break;
		}
	}

	pam_setcred(auth_handle, PAM_REFRESH_CRED);

	if (pam_end(auth_handle, pam_status) != PAM_SUCCESS) {
		swaylock_log(LOG_ERROR, "pam_end failed");
		exit(EXIT_FAILURE);
	}

	exit((pam_status == PAM_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE);
}

static int fp_conversation(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *data) {
	struct pam_response *pam_reply =
		calloc(num_msg, sizeof(struct pam_response));
	if (pam_reply == NULL) {
		swaylock_log(LOG_ERROR, "Allocation failed");
		return PAM_ABORT;
	}
	*resp = pam_reply;
	for (int i = 0; i < num_msg; ++i) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			/* A fingerprint-only stack must never ask for a password. If it
			 * does, /etc/pam.d/swaylock-fp is misconfigured; bail rather than
			 * silently block. */
			swaylock_log(LOG_ERROR,
				"fingerprint PAM service requested input; check that "
				"/etc/pam.d/swaylock-fp contains only pam_fprintd");
			return PAM_CONV_ERR;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			swaylock_log(LOG_DEBUG, "fingerprint: %s", msg[i]->msg);
			break;
		}
	}
	return PAM_SUCCESS;
}

void run_fp_backend_child(void) {
	struct passwd *passwd = getpwuid(getuid());
	if (!passwd) {
		swaylock_log_errno(LOG_ERROR, "getpwuid failed");
		exit(EXIT_FAILURE);
	}
	char *username = passwd->pw_name;

	/* Block until the parent enables fingerprint auth (--fingerprint). If the
	 * parent goes away before then, just exit quietly. */
	if (!wait_fp_start()) {
		exit(EXIT_SUCCESS);
	}

	const struct pam_conv conv = {
		.conv = fp_conversation,
		.appdata_ptr = NULL,
	};
	pam_handle_t *auth_handle = NULL;
	if (pam_start("swaylock-fp", username, &conv, &auth_handle) != PAM_SUCCESS) {
		swaylock_log(LOG_ERROR, "pam_start failed for fingerprint service");
		exit(EXIT_FAILURE);
	}

	/* Permanent verify loop. pam_fprintd allows a few finger attempts per
	 * pam_authenticate() call, then returns; we retry forever (with a short
	 * backoff) so the user gets effectively unlimited finger attempts. This
	 * runs entirely independently of the password child, so a pending or
	 * failed scan never blocks typing. The loop ends when a finger matches, or
	 * when the parent kills us after a password unlock / shutdown. */
	int pam_status = PAM_AUTH_ERR;
	while (1) {
		struct timespec t0, t1;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		pam_status = pam_authenticate(auth_handle, 0);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		bool success = pam_status == PAM_SUCCESS;
		if (!write_fp_reply(success)) {
			break; // parent is gone
		}
		if (success) {
			break;
		}

		/* A genuine wrong-finger attempt makes pam_fprintd block for a touch and
		 * run the device activate + TLS handshake, costing seconds. If
		 * pam_authenticate fails almost instantly, no finger was read: the
		 * fprintd verify session is dead ("verify-disconnected"). This happens
		 * when the Goodix sensor re-enumerates onto a new USB address after
		 * idle/sleep and leaves the running daemon bound to a stale fd. Left
		 * alone, every retry fails the same way and swaylock loops "Wrong"
		 * forever with no finger touch. Restart fprintd so dbus reactivates a
		 * fresh, correctly-bound daemon, then wait for the USB device to settle
		 * before retrying. This is timing-independent: it heals both the
		 * re-enumeration case and a bare stale-TLS session. */
		double elapsed = (t1.tv_sec - t0.tv_sec) +
			(t1.tv_nsec - t0.tv_nsec) / 1000000000.0;
		if (elapsed < 1.5) {
			if (system("/usr/bin/sudo -n /usr/local/bin/fprintd-restart"
					" >/dev/null 2>&1") != 0) {
				swaylock_log(LOG_DEBUG,
					"fprintd self-heal restart command failed");
			}
			struct timespec settle = { .tv_sec = 1, .tv_nsec = 500 * 1000 * 1000 };
			nanosleep(&settle, NULL);
			continue;
		}

		/* Brief back-off so we neither hammer the reader nor spin if the device
		 * is momentarily unavailable (e.g. mid-release after a failed match). */
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}

	if (pam_status == PAM_SUCCESS) {
		pam_setcred(auth_handle, PAM_REFRESH_CRED);
	}
	pam_end(auth_handle, pam_status);
	exit((pam_status == PAM_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE);
}
