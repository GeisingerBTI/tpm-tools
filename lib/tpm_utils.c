/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

#include "config.h"
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#include "tpm_tspi.h"
#include "tpm_utils.h"

BOOL useUnicode = FALSE;

static const struct option sGenLongOpts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ "log", required_argument, NULL, 'l' },
	{ "unicode", no_argument, NULL, 'u' },
};

static const char *pszGenShortOpts = "hvl:u";

void initIntlSys(void) {

	setlocale( LC_ALL, "" );
	bindtextdomain( PACKAGE, LOCALEDIR );
	textdomain( PACKAGE );
}

int
genericOptHandler( int a_iNumArgs, char **a_pszArgs,
		   const char *a_pszShortOpts,
		   struct option *a_sLongOpts, int a_iNumOpts,
		   CmdOptParser a_tCmdOptParser, CmdHelpFunction a_tCmdHelpFunction ) {

	CmdHelpFunction  tCmdHelp = ( a_tCmdHelpFunction ) ? a_tCmdHelpFunction
							   : logCmdHelp;

	char  szShortOpts[64];

	int            iNumGenLongOpts = sizeof( sGenLongOpts ) / sizeof( struct option );
	struct option  sLongOpts[64];

	int  iOpt;
	int  rc;

	strcpy( szShortOpts, pszGenShortOpts);
	if ( a_pszShortOpts )
		strcat( szShortOpts, a_pszShortOpts );

	memset( sLongOpts, 0, sizeof( sLongOpts ) );
	memcpy( sLongOpts, sGenLongOpts, sizeof( sGenLongOpts ) );
	if ( a_sLongOpts ) {
		memcpy( sLongOpts + iNumGenLongOpts,
			a_sLongOpts,
			a_iNumOpts * sizeof( struct option ) );
	}

	while ( ( iOpt = getopt_long( a_iNumArgs, a_pszArgs,
					szShortOpts, sLongOpts, NULL ) ) != -1 ) {

		switch ( iOpt ) {
			case 'h':
				tCmdHelp( a_pszArgs[0] );
				return -1;

			case 'v':
				logMsg( _("%s version: %s\n"), a_pszArgs[0], CMD_VERSION );
				return -1;

			case 'l':
				if ( !optarg ) {
					tCmdHelp( a_pszArgs[0] );
					return -1;
				}

				if ( strcmp( optarg, LOG_NONE ) == 0 )
					iLogLevel = LOG_LEVEL_NONE;
				else if ( strcmp( optarg, LOG_ERROR ) == 0 )
					iLogLevel = LOG_LEVEL_ERROR;
				else if ( strcmp( optarg, LOG_INFO ) == 0 )
					iLogLevel = LOG_LEVEL_INFO;
				else if ( strcmp( optarg, LOG_DEBUG ) == 0 )
					iLogLevel = LOG_LEVEL_DEBUG;
				else {
					logMsg( _("Valid log levels are: %s, %s, %s, %s\n"),
						LOG_NONE,
						LOG_ERROR,
						LOG_INFO,
						LOG_DEBUG );
					tCmdHelp( a_pszArgs[0] );
					return -1;
				}
				break;
			case 'u':
				useUnicode = TRUE;
				break;
			case '?':
				tCmdHelp( a_pszArgs[0] );
				return -1;

			default:
				if ( !a_tCmdOptParser )
					return -1;

				rc = a_tCmdOptParser( iOpt, optarg );
				if ( rc != 0 )
					return rc;
				break;
		}
	}

	return 0;
}

/*
 * This function should be called when you are done with a password
 * the above getPasswd function to properly clean up.
 */
void shredPasswd( char *a_pszPasswd ) {

	if ( a_pszPasswd ) {
		memset( a_pszPasswd, 0, strlen( a_pszPasswd ) );
		free( a_pszPasswd );
	}
}

/*
 * You must free the memory passed back to you when you are finished.
 * Loop will always terminate by the second pass.
 * Safest use of getpass is to zero the memory as soon as possible.
 */
char *getPlainPasswd(const char *a_pszPrompt, BOOL a_bConfirm) {
	int len;
	return _getPasswd(a_pszPrompt, &len, a_bConfirm, FALSE);
}

#ifndef TSS_LIB_IS_12
char *getPasswd(const char *a_pszPrompt, int* a_iLen, 
		BOOL a_bConfirm) {
	return _getPasswd( a_pszPrompt, a_iLen, a_bConfirm, useUnicode);
}
#endif

#define __SET_ECHO_ON	1
#define __SET_ECHO_OFF	0

int __set_echo(int on, tcflag_t *old_flag) {
	int err;
	struct termios term;

	if (tcgetattr(STDIN_FILENO, &term) == -1) {
		logError("Cannot get terminal attributes");
		return 1;
	}

	if (on) {
		term.c_lflag = *old_flag;
	} else {
		*old_flag = term.c_lflag;
		term.c_lflag &= ~ECHO;
		term.c_lflag |= (ECHOE | ECHOK | ECHONL | ICANON);
	}

	err = tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
	if (err) {
		logError("Cannot set terminal attributes");
		return 1;
	}

	return 0;
}

char *_getPasswd(const char *a_pszPrompt, int* a_iLen, 
		BOOL a_bConfirm, BOOL a_bUseUnicode) {

	char *pszPrompt = (char *)a_pszPrompt;
	char *pszRetPasswd = NULL;
	char buf1[256], buf2[256];
	int items;
	tcflag_t old_flag;

	printf("%s", a_pszPrompt);
	memset(buf1, 0, sizeof(buf1));

	if (__set_echo(__SET_ECHO_OFF, &old_flag))
		return NULL;

	items = scanf("%255s", buf1);
	if (items != 1)
		goto out;

	if (a_bConfirm) {
		pszPrompt = _("Confirm password: ");

		printf("%s", pszPrompt);
		memset(buf2, 0, sizeof(buf2));

		items = scanf("%255s", buf2);
		if (items != 1)
			goto out;

		if (memcmp(buf1, buf2, sizeof(buf1))) {
			// No match clean-up
			logMsg( _("Passwords didn't match\n") );
			goto out;
		}
	}

	*a_iLen = strlen(buf1);

	if (a_bUseUnicode) {
		pszRetPasswd = (char *)Trspi_Native_To_UNICODE((BYTE *)buf1, (unsigned int *)a_iLen);
	} else {
		pszRetPasswd = strdup(buf1);
	}
out:
	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));

	__set_echo(__SET_ECHO_ON, &old_flag);

	return pszRetPasswd;
}

/*
 * You must free the memory passed back to you when you are finished.
 */
char *getReply( const char *a_pszPrompt, int a_iMaxLen ) {

	char *pszReply  = NULL;
	int   iReplyLen = a_iMaxLen + 2; // Room for newline and trailing zero

	if ( iReplyLen <= 0 )
		goto out;

	pszReply = (char *)calloc( iReplyLen, 1 );
	if ( !pszReply )
		goto out;

	logMsg( "%s", a_pszPrompt );
	pszReply = fgets( pszReply, iReplyLen, stdin );
	if ( !pszReply )
		goto out;

	// Be certain that a complete line was read
	if ( ( pszReply[ a_iMaxLen ] != '\n' ) && ( pszReply[ a_iMaxLen ] != '\0' ) ) {
		free( pszReply );
		pszReply = NULL;
		goto out;
	}

	for ( iReplyLen -= 1; iReplyLen >= 0; iReplyLen-- ) {
		if ( pszReply[ iReplyLen ] == '\0' )
			continue;

		if ( pszReply[ iReplyLen ] == '\n' )
			pszReply[ iReplyLen ] = '\0';
		break;
	}

out:
	return pszReply;
}
