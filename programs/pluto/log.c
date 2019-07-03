/* error logging functions, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <pthread.h>    /* Must be the first include file; XXX: why? */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "defs.h"
#include "lswlog.h"
#include "log.h"
#include "peerlog.h"
#include "state_db.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"	/* for kernel_ops */
#include "timer.h"
#include "ip_endpoint.h"
#include "impair.h"
#include "demux.h"	/* for struct msg_digest */

bool
	log_to_stderr = TRUE,		/* should log go to stderr? */
	log_to_syslog = TRUE,		/* should log go to syslog? */
	log_with_timestamp = TRUE,	/* testsuite requires no timestamps */
	log_append = TRUE,
	log_to_audit = FALSE;

char *pluto_log_file = NULL;	/* pathname */
static FILE *pluto_log_fp = NULL;

char *pluto_stats_binary = NULL;

/*
 * If valid, wack and log_whack streams write to this.
 *
 * (apparently) If the context provides a whack file descriptor,
 * messages should be copied to it -- see whack_log()
 */
fd_t whack_log_fd = { .fd = NULL_FD, };      /* only set during whack_handle() */

/*
 * Context for logging.
 *
 * CUR_FROM, CUR_CONNECTION and CUR_STATE work something like a stack.
 * lswlog_log_prefix() will use the first of CUR_STATE, CUR_CONNECTION
 * and CUR_FROM when looking for the context to use with a prefix.
 * Operations then "push" and "pop" (or clear all) contexts.
 *
 * For instance, setting CUR_STATE will hide CUR_CONNECTION, and
 * resetting CUR_STATE will re-expose CUR_CONNECTION.
 *
 * Surely it would be easier to explicitly specify the context with
 * something like LSWLOG_RC_STATE()?
 *
 * Global variables: must be carefully adjusted at transaction
 * boundaries!
 */
static struct state *cur_state = NULL;                 /* current state, for diagnostics */
static struct connection *cur_connection = NULL;       /* current connection, for diagnostics */
static ip_address cur_from;				/* source of current current message */

static void update_extra(const char *what, enum_names *names,
			 lmod_t extra, lset_t mask)
{
	if (!lmod_empty(extra)) {
		lset_t old = base_debugging & mask;
		lset_t new = lmod(old, extra);
		if (new != old) {
			LSWLOG(buf) {
				lswlogf(buf, "extra %s enabled for connection: ", what);
				lswlog_enum_lset_short(buf, names, "+", new & ~old);
				/* XXX: doesn't log cleared */
			}
			set_debugging(new | (base_debugging & ~mask));
		}
	}
}

static void update_debugging(void)
{
	struct connection *c = cur_state != NULL ? cur_state->st_connection : cur_connection;
	if (c == NULL) {
		set_debugging(base_debugging);
	} else {
		update_extra("debugging", &debug_names,
			     c->extra_debugging, DBG_MASK);
		update_extra("impairing", &impair_names,
			     c->extra_impairing, IMPAIR_MASK);
	}
}

/*
 * if any debugging is on, make sure that we log the connection we are
 * processing, because it may not be clear in later debugging.
 */

enum processing {
	START = 1,
	STOP,
	RESTART,
	SUSPEND,
	RESUME,
	RESET,
};

static void log_processing(enum processing processing, bool current,
			   struct state *st, struct connection *c,
			   const ip_address *from,
			   const char *func, const char *file, long line)
{
	pexpect(((st != NULL) + (c != NULL) + (from != NULL)) == 1);	/* exactly 1 */
	LSWDBGP(DBG_BASE, buf) {
		switch (processing) {
		case START: jam(buf, "start"); break;
		case STOP: jam(buf, "stop"); break;
		case RESTART: jam(buf, "[RE]START"); break;
		case SUSPEND: jam(buf, "suspend"); break;
		case RESUME: jam(buf, "resume"); break;
		case RESET: jam(buf, "RESET"); break;
		}
		jam(buf, " processing:");
		if (st != NULL) {
			jam(buf, " state #%lu", st->st_serialno);
			/* also include connection/from */
			c = st->st_connection;
			from = &st->st_remoteaddr;
		}
		if (c != NULL) {
			jam_string(buf, " connection ");
			jam_connection(buf, c);
		}
		if (from != NULL) {
			lswlogf(buf, " from ");
			jam_endpoint(buf, from);
		}
		if (!current) {
			jam(buf, " (BACKGROUND)");
		}
		lswlog_source_line(buf, func, file, line);
	}
}

/*
 * XXX:
 *
 * Given code should be using matching push/pop operations on each
 * field, this global 'blat' looks like some sort of - we've lost
 * track - hack.  Especially since the reset_globals() call is often
 * followed by passert(globals_are_reset()).
 *
 * Is this leaking the whack_log_fd?
 *
 * For instance, the IKEv1/IKEv2 specific initiate code calls
 * reset_globals() when it probably should be calling pop_cur_state().
 * Luckily, whack_log_fd isn't the real value (that seems to be stored
 * elsewhere?) and, for as long as the whack connection is up, code
 * keeps setting it back.
 */
void log_reset_globals(const char *func, const char *file, long line)
{
	if (fd_p(whack_log_fd)) {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "processing: RESET whack log_fd (was "PRI_FD")",
				PRI_fd(whack_log_fd));
			lswlog_source_line(buf, func, file, line);
		}
		whack_log_fd = null_fd;
	}
	if (cur_state != NULL) {
		log_processing(RESET, true, cur_state, NULL, NULL,
			       func, file, line);
		cur_state = NULL;
	}
	if (cur_connection != NULL) {
		log_processing(RESET, true, NULL, cur_connection, NULL,
			       func, file, line);
		cur_connection = NULL;
	}
	if (isvalidaddr(&cur_from)) {
		/* peer's IP address */
		log_processing(RESET, true, NULL, NULL, &cur_from,
			       func, file, line);
		zero(&cur_from);
	}
	if (cur_debugging != base_debugging) {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "processing: RESET cur_debugging (was "PRI_LSET")",
				cur_debugging);
			lswlog_source_line(buf, func, file, line);
		}
		cur_debugging = base_debugging;
	}
}

void log_pexpect_reset_globals(const char *func, const char *file, long line)
{
	if (fd_p(whack_log_fd)) {
		LSWLOG_PEXPECT_SOURCE(func, file, line, buf) {
			lswlogf(buf, "processing: unexpected whack_log_fd "PRI_FD" should be "PRI_FD,
				PRI_fd(whack_log_fd), PRI_fd(null_fd));
		}
		whack_log_fd = null_fd;
	}
	if (cur_state != NULL) {
		LSWLOG_PEXPECT_SOURCE(func, file, line, buf) {
			lswlogf(buf, "processing: unexpected cur_state #%lu should be #0",
				cur_state->st_serialno);
		}
		cur_state = NULL;
	}
	if (cur_connection != NULL) {
		LSWLOG_PEXPECT_SOURCE(func, file, line, buf) {
			lswlogf(buf, "processing: unexpected cur_connection %s should be NULL",
				cur_connection->name);
		}
		cur_connection = NULL;
	}
	if (isvalidaddr(&cur_from)) {
		LSWLOG_PEXPECT_SOURCE(func, file, line, buf) {
			lswlogs(buf, "processing: unexpected cur_from ");
			jam_sensitive_endpoint(buf, &cur_from);
			lswlogs(buf, " should be NULL");
		}
		zero(&cur_from);
	}
	if (cur_debugging != base_debugging) {
		LSWLOG_PEXPECT_SOURCE(func, file, line, buf) {
			lswlogf(buf, "processing: unexpected cur_debugging "PRI_LSET" should be "PRI_LSET,
				cur_debugging, base_debugging);
		}
		cur_debugging = base_debugging;
	}
}

struct connection *log_push_connection(struct connection *new_connection, const char *func,
				       const char *file, long line)
{
	bool current = (cur_state == NULL); /* not hidden by state? */
	struct connection *old_connection = cur_connection;

	if (old_connection != NULL &&
	    old_connection != new_connection) {
		log_processing(SUSPEND, current,
			       NULL, old_connection, NULL,
			       func, file, line);
	}

	cur_connection = new_connection;
	update_debugging();

	if (new_connection == NULL) {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "start processing: connection NULL");
			lswlog_source_line(buf, func, file, line);
		}
	} else if (old_connection == new_connection) {
		log_processing(RESTART, current,
			       NULL, new_connection, NULL,
			       func, file, line);
	} else {
		log_processing(START, current,
			       NULL, new_connection, NULL,
			       func, file, line);
	}

	return old_connection;
}

void log_pop_connection(struct connection *c, const char *func,
			const char *file, long line)
{
	bool current = (cur_state == NULL); /* not hidden by state? */
	if (cur_connection != NULL) {
		log_processing(STOP, current /* current? */,
			       NULL, cur_connection, NULL,
			       func, file, line);
	} else {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "processing: STOP connection NULL");
			lswlog_source_line(buf, func, file, line);
		}
	}
	cur_connection = c;
	update_debugging();
	if (cur_connection != NULL) {
		log_processing(RESUME, current /* current? */,
			       NULL, cur_connection, NULL,
			       func, file, line);
	}
}

bool is_cur_connection(const struct connection *c)
{
	return cur_connection == c;
}

so_serial_t log_push_state(struct state *new_state, const char *func,
			   const char *file, long line)
{
	struct state *old_state = cur_state;

	if (old_state != NULL) {
		if (old_state != new_state) {
			log_processing(SUSPEND, true /* must be current */,
				       cur_state, NULL, NULL,
				       func, file, line);
		}
	} else if (cur_connection != NULL && new_state != NULL) {
		log_processing(SUSPEND, true /* current for now */,
			       NULL, cur_connection, NULL,
			       func, file, line);
	}

	cur_state = new_state;
	update_debugging();

	if (new_state == NULL) {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "skip start processing: state #0");
			lswlog_source_line(buf, func, file, line);
		}
	} else if (old_state == new_state) {
		log_processing(RESTART, true /* must be current */,
			       new_state, NULL, NULL,
			       func, file, line);
	} else {
		log_processing(START, true /* must be current */,
			       new_state, NULL, NULL,
			       func, file, line);
	}
	return old_state != NULL ? old_state->st_serialno : SOS_NOBODY;
}

void log_pop_state(so_serial_t serialno, const char *func,
		   const char *file, long line)
{
	if (cur_state != NULL) {
		log_processing(STOP, true, /* must be current */
			       cur_state, NULL, NULL,
			       func, file, line);
	} else {
		LSWDBGP(DBG_BASE, buf) {
			lswlogf(buf, "processing: STOP state #0");
			lswlog_source_line(buf, func, file, line);
		}
	}
	cur_state = state_by_serialno(serialno);
	update_debugging();
	if (cur_state != NULL) {
		log_processing(RESUME, true, /* must be current */
			       cur_state, NULL, NULL,
			       func, file, line);
	} else if (cur_connection != NULL) {
		log_processing(RESUME, true, /* now current */
			       NULL, cur_connection, NULL,
			       func, file, line);
	}
}

extern ip_address log_push_from(ip_address new_from,
				const char *func,
				const char *file, long line)
{
	bool current = (cur_state == NULL && cur_connection == NULL);
	ip_address old_from = cur_from;
	if (isvalidaddr(&old_from)) {
		log_processing(SUSPEND, current,
			       NULL, NULL, &old_from,
			       func, file, line);
	}
	cur_from = new_from;
	if (isvalidaddr(&cur_from)) {
		log_processing(START, current,
			       NULL, NULL, &cur_from,
			       func, file, line);
	}
	return old_from;
}

extern void log_pop_from(ip_address old_from,
			 const char *func,
			 const char *file, long line)
{
	bool current = (cur_state == NULL && cur_connection == NULL);
	if (isvalidaddr(&cur_from)) {
		log_processing(STOP, current,
			       NULL, NULL, &cur_from,
			       func, file, line);
	}
	if (isvalidaddr(&old_from)) {
		log_processing(RESUME, current,
			       NULL, NULL, &old_from,
			       func, file, line);
	}
	cur_from = old_from;
}


/*
 * Initialization.
 */

void pluto_init_log(void)
{
	set_alloc_exit_log_func(exit_log);
	if (log_to_stderr)
		setbuf(stderr, NULL);

	if (pluto_log_file != NULL) {
		pluto_log_fp = fopen(pluto_log_file,
			log_append ? "a" : "w");
		if (pluto_log_fp == NULL) {
			fprintf(stderr,
				"Cannot open logfile '%s': %s\n",
				pluto_log_file, strerror(errno));
		} else {
			/*
			 * buffer by line:
			 * should be faster that no buffering
			 * and yet safe since each message is probably a line.
			 */
			setvbuf(pluto_log_fp, NULL, _IOLBF, 0);
		}
	}

	if (log_to_syslog)
		openlog("pluto", LOG_CONS | LOG_NDELAY | LOG_PID,
			LOG_AUTHPRIV);

	peerlog_init();
}

/*
 * Add just the WHACK or STATE (or connection) prefix.
 *
 * Callers need to pick and choose.  For instance, WHACK output some
 * times suppress the whack prefix; and there is no point adding the
 * STATE prefix when it was added earlier.
 */

static void add_whack_rc_prefix(struct lswlog *buf, enum rc_type rc)
{
	lswlogf(buf, "%03d ", rc);
}

/*
 * Wrap up the logic to decide if a particular output should occur.
 * The compiler will likely inline these.
 */

static void stdlog_raw(char *b)
{
	if (log_to_stderr || pluto_log_fp != NULL) {
		FILE *out = log_to_stderr ? stderr : pluto_log_fp;

		if (log_with_timestamp) {
			char now[34] = "";
			struct realtm t = local_realtime(realnow());
			strftime(now, sizeof(now), "%b %e %T", &t.tm);
			fprintf(out, "%s.%06ld: %s\n", now, t.microsec, b);
		} else {
			fprintf(out, "%s\n", b);
		}
	}
}

static void syslog_raw(int severity, char *b)
{
	if (log_to_syslog)
		syslog(severity, "%s", b);
}

static void peerlog_raw(char *b)
{
	if (log_to_perpeer) {
		peerlog(cur_connection, b);
	}
}

static void whack_raw(struct lswlog *b, enum rc_type rc)
{
	/*
	 * Only whack-log when the main thread.
	 *
	 * Helper threads, which are asynchronous, shouldn't be trying
	 * to directly emit whack output.
	 */
	if (in_main_thread()) {
		if (whack_log_p()) {
			/*
			 * On the assumption that logging to whack is
			 * rare and slow anyway, don't try to tune
			 * this code path.
			 */
			LSWBUF(buf) {
				add_whack_rc_prefix(buf, rc);
				/* add_state_prefix() - done by caller */
				lswlogl(buf, b);
				lswlog_to_whack_stream(buf);
			}
		}
	}
}

static void lswlog_cur_prefix(struct lswlog *buf,
			      const struct state *cur_state,
			      const struct connection *cur_connection,
			      const ip_address *cur_from)
{
	if (!in_main_thread()) {
		return;
	}

	const struct connection *c = cur_state != NULL ? cur_state->st_connection :
		cur_connection;

	if (c != NULL) {
		jam_connection(buf, c);
		if (cur_state != NULL) {
			/* state number */
			lswlogf(buf, " #%lu", cur_state->st_serialno);
			/* state name */
			if (DBGP(DBG_ADD_PREFIX)) {
				lswlogf(buf, " ");
				lswlogs(buf, cur_state->st_state->short_name);
			}
		}
		lswlogs(buf, ": ");
	} else if (cur_from != NULL && isvalidaddr(cur_from)) {
		/* peer's IP address */
		lswlogs(buf, "packet from ");
		jam_sensitive_endpoint(buf, cur_from);
		lswlogs(buf, ": ");
	}
}

void lswlog_log_prefix(struct lswlog *buf)
{
	lswlog_cur_prefix(buf, cur_state, cur_connection, &cur_from);
}

/*
 * This needs to mimic both lswlog_log_prefix() and
 * lswlog_dbg_prefix().
 */

void log_prefix(struct lswlog *buf, bool debug,
		struct state *st, struct connection *c)
{
	if (debug) {
		lswlogs(buf, DEBUG_PREFIX);
	}
	if (!debug || DBGP(DBG_ADD_PREFIX)) {
		lswlog_cur_prefix(buf, st, c, &cur_from);
	}
}

bool log_debugging(struct state *st, struct connection *c,
		   lset_t debug)
{
	if (st != NULL) {
		c = st->st_connection;
	}
	if (c == NULL) {
		return base_debugging & debug;
	} else {
		lset_t debugging = lmod(base_debugging, c->extra_debugging);
		return debugging & debug;
	}
}

static void log_raw(struct lswlog *buf, int severity)
{
	stdlog_raw(buf->array);
	syslog_raw(severity, buf->array);
	peerlog_raw(buf->array);
	/* not whack */
}

void lswlog_to_debug_stream(struct lswlog *buf)
{
	sanitize_string(buf->array, buf->roof); /* needed? */
	log_raw(buf, LOG_DEBUG);
	/* not whack */
}

void lswlog_to_error_stream(struct lswlog *buf)
{
	log_raw(buf, LOG_ERR);
	whack_raw(buf, RC_LOG_SERIOUS);
}

void lswlog_to_log_stream(struct lswlog *buf)
{
	log_raw(buf, LOG_WARNING);
	/* not whack */
}

void lswlog_to_default_streams(struct lswlog *buf, enum rc_type rc)
{
	log_raw(buf, LOG_WARNING);
	whack_raw(buf, rc);
}

void close_log(void)
{
	if (log_to_syslog)
		closelog();

	if (pluto_log_fp != NULL) {
		(void)fclose(pluto_log_fp);
		pluto_log_fp = NULL;
	}

	peerlog_close();
}

/* <prefix><state#N...><message>. Errno %d: <strerror> */

void lswlog_errno_prefix(struct lswlog *buf, const char *prefix)
{
	lswlogs(buf, prefix);
	lswlog_log_prefix(buf);
}

void lswlog_errno_suffix(struct lswlog *buf, int e)
{
	lswlogs(buf, ".");
	jam(buf, " "PRI_ERRNO, pri_errno(e));
	lswlog_to_error_stream(buf);
}

void exit_log(const char *message, ...)
{
	LSWBUF(buf) {
		/* FATAL ERROR: <state...><message> */
		lswlogs(buf, "FATAL ERROR: ");
		lswlog_log_prefix(buf);
		va_list args;
		va_start(args, message);
		lswlogvf(buf, message, args);
		va_end(args);
		lswlog_to_error_stream(buf);
	}
	exit_pluto(PLUTO_EXIT_FAIL);
}

void libreswan_exit(enum rc_type rc)
{
	exit_pluto(rc);
}

void whack_log_pre(enum rc_type rc, struct lswlog *buf)
{
	passert(in_main_thread());
	add_whack_rc_prefix(buf, rc);
	lswlog_log_prefix(buf);
}

void lswlog_to_whack_stream(struct lswlog *buf)
{
	passert(in_main_thread());

	fd_t wfd = fd_p(whack_log_fd) ? whack_log_fd :
		cur_state != NULL ? cur_state->st_whack_sock :
		null_fd;

	passert(fd_p(wfd));

	/* m includes '\0' */
	chunk_t m = jambuf_as_chunk(buf);

	/* don't need NUL, do need NL */
	passert(m.ptr[m.len-1] == '\0');
	m.ptr[m.len-1] = '\n';

	/* write to whack socket, but suppress possible SIGPIPE */
#ifdef MSG_NOSIGNAL                     /* depends on version of glibc??? */
	(void) send(wfd.fd, m.ptr, m.len, MSG_NOSIGNAL);
#else /* !MSG_NOSIGNAL */
	int r;
	struct sigaction act, oldact;

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; /* no nothing */
	r = sigaction(SIGPIPE, &act, &oldact);
	passert(r == 0);

	(void) write(wfd, m.ptr, m.len);

	r = sigaction(SIGPIPE, &oldact, NULL);
	passert(r == 0);
#endif /* !MSG_NOSIGNAL */
	m.ptr[m.len-1] = '\0'; /* put NUL back */
}

bool whack_log_p(void)
{
	if (!in_main_thread()) {
		PEXPECT_LOG("%s", "whack_log*() must be called from the main thread");
		return false;
	}

	fd_t wfd = fd_p(whack_log_fd) ? whack_log_fd :
	      cur_state != NULL ? cur_state->st_whack_sock :
	      null_fd;

	return fd_p(wfd);
}

/* emit message to whack.
 * form is "ddd statename text" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */

void whack_log(enum rc_type rc, const char *message, ...)
{
	if (whack_log_p()) {
		LSWBUF(buf) {
			add_whack_rc_prefix(buf, rc);
			lswlog_log_prefix(buf);
			va_list args;
			va_start(args, message);
			lswlogvf(buf, message, args);
			va_end(args);
			lswlog_to_whack_stream(buf);
		}
	}
}

void whack_log_comment(const char *message, ...)
{
	if (whack_log_p()) {
		LSWBUF(buf) {
			/* add_whack_rc_prefix() - skipped */
			lswlog_log_prefix(buf);
			va_list args;
			va_start(args, message);
			lswlogvf(buf, message, args);
			va_end(args);
			lswlog_to_whack_stream(buf);
		}
	}
}

lset_t base_debugging = DBG_NONE; /* default to reporting nothing */

void set_debugging(lset_t deb)
{
	cur_debugging = deb;
}

void reset_debugging(void)
{
	set_debugging(base_debugging);
}

void plog_raw(const struct state *st,
	      const struct connection *c,
	      const ip_endpoint *from,
	      const char *message, ...)
{
	LSWBUF(buf) {
		lswlog_cur_prefix(buf, st, c, from);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
	}
}

#define RATE_LIMIT 1000
static unsigned nr_rate_limited_logs;

static unsigned log_limit(void)
{
	if (impair_log_rate_limit == 0) {
		/* --impair log-rate-limit:no */
		return RATE_LIMIT;
	} else {
		/* --impair log-rate-limit:yes */
		/* --impair log-rate-limit:NNN */
		return impair_log_rate_limit;
	}
}

void rate_log(const struct msg_digest *md,
	      const char *message, ...)
{
	unsigned limit = log_limit();
	if (nr_rate_limited_logs == limit) {
		plog_global("rate limited log reached limit of %u entries", limit);
	} else if (nr_rate_limited_logs > limit) {
		LSWDBGP(DBG_BASE, buf) {
			va_list ap;
			va_start(ap, message);
			lswlogvf(buf, message, ap);
			va_end(ap);
		}
		return;
	}
	nr_rate_limited_logs++;
	LSWBUF(buf) {
		lswlog_cur_prefix(buf, NULL/*st*/, NULL/*c*/, &md->sender);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		lswlog_to_log_stream(buf);
	}
}

static void reset_log_rate_limit(void)
{
	if (nr_rate_limited_logs > log_limit()) {
		plog_global("rate limited log reset");
	}
	nr_rate_limited_logs = 0;
}

void init_rate_log(void)
{
	enable_periodic_timer(EVENT_RESET_LOG_RATE_LIMIT,
			      reset_log_rate_limit,
			      RESET_LOG_RATE_LIMIT);
}
