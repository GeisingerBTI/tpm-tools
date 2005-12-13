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

#include "data_init.h"
#include "data_common.h"

#include <tpm_pkcs11.h>
#include <tpm_utils.h>

#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>


BOOL  g_bYes    = FALSE;

/*
 * parseCallback
 *   Process the command specific options.
 */
int
parseCallback( int         a_iOpt,
               const char *a_pszOptArg ) {

	switch ( a_iOpt ) {
		case 'y':
			g_bYes = TRUE;
			break;
	}

	return 0;
}

/*
 * usageCallback
 *   Display command usage information.
 */
void
usageCallback( const char *a_pszCmd ) {

	logCmdHelp( a_pszCmd );
	logCmdOption( "-y, --yes",
			_("Reply 'yes' to the clear TPM token prompt") );
}

/*
 * parseCmd
 *   Parse the command line options.
 */
int
parseCmd( int    a_iArgc,
          char **a_pszArgv ) {

	char *pszShortOpts = "y";
	struct option  stLongOpts[] = {
					{ "yes", no_argument, NULL, 'y' },
				};
	int  iNumLongOpts = sizeof( stLongOpts ) / sizeof( struct option );

	return genericOptHandler( a_iArgc, a_pszArgv,
					pszShortOpts, stLongOpts, iNumLongOpts,
					parseCallback, usageCallback );
}

int
main( int    a_iArgc,
      char **a_pszArgv ) {

	int  rc = 1;

	// Create buffers for PIN prompts for formatting using sprintf
	char  szSoNewPinPrompt[ strlen( TOKEN_SO_NEW_PIN_PROMPT ) + 16 ];
	char  szUserNewPinPrompt[ strlen( TOKEN_USER_NEW_PIN_PROMPT ) + 16 ];

	char *pszReply      = NULL;
	char *pszSoPin      = NULL;
	char *pszNewSoPin   = NULL;
	char *pszNewUserPin = NULL;

	CK_RV              rv       = CKR_OK;
	CK_SESSION_HANDLE  hSession = 0;

	// Set up i18n
	initIntlSys( );

	// Parse the command
	if ( parseCmd( a_iArgc, a_pszArgv ) == -1 )
		goto out;

	// Open the PKCS#11 TPM Token
	rv = openToken( );
	if ( rv != CKR_OK )
		goto out;

	// Check if the token is already initialized
	if ( isTokenInitialized( ) ) {
		// Warn and ask the user before clearing
		if ( !g_bYes ) {
			pszReply = getReply( TOKEN_CLEAR_PROMPT, 1 );
			if ( !pszReply ||
				( strlen( pszReply ) == 0 ) ||
				( strcasecmp( pszReply, TOKEN_CLEAR_NO ) == 0 ) ) {
				goto done;
			}
		}

		// Prompt for the current SO password
		pszSoPin = getPlainPasswd( TOKEN_SO_PIN_PROMPT, FALSE );
		if ( !pszSoPin )
			goto done;
	}
	else
		pszSoPin = strdup( TOKEN_SO_INIT_PIN );

	// Clear the TPM token
	rv = initToken( pszSoPin );
	if ( rv != CKR_OK )
		goto done;

	// Open a session
	rv = openTokenSession( CKF_RW_SESSION, &hSession );
	if ( rv != CKR_OK )
		goto done;

	// Login to the token
	rv = loginToken( hSession, CKU_SO, TOKEN_SO_INIT_PIN );
	if ( rv != CKR_OK )
		goto done;

	sprintf( szSoNewPinPrompt, TOKEN_SO_NEW_PIN_PROMPT, getMinPinLen( ), getMaxPinLen( ) );
	while ( TRUE ) {
		// Prompt for a new SO password
		pszNewSoPin = getPlainPasswd( szSoNewPinPrompt, TRUE );
		if ( !pszNewSoPin )
			goto done;

		// Set the new password
		rv = setPin( hSession, TOKEN_SO_INIT_PIN, pszNewSoPin );
		if ( rv == CKR_OK )
			break;

		if ( ( rv == CKR_PIN_INVALID ) || ( rv == CKR_PIN_LEN_RANGE ) )
			logError( TOKEN_INVALID_PIN );
		else
			goto done;

		shredPasswd( pszNewSoPin );
	}

	// Open a new session
	closeTokenSession( hSession );
	hSession = 0;
	rv = openTokenSession( CKF_RW_SESSION, &hSession );
	if ( rv != CKR_OK )
		goto done;

	// Login to the token
	rv = loginToken( hSession, CKU_USER, TOKEN_USER_INIT_PIN );
	if ( rv != CKR_OK )
		goto done;

	sprintf( szUserNewPinPrompt, TOKEN_USER_NEW_PIN_PROMPT, getMinPinLen( ), getMaxPinLen( ) );
	while ( TRUE ) {
		// Prompt for a new User password
		pszNewUserPin = getPlainPasswd( szUserNewPinPrompt, TRUE );
		if ( !pszNewUserPin )
			goto done;

		// Set the new password
		rv = setPin( hSession, TOKEN_USER_INIT_PIN, pszNewUserPin );
		if ( rv == CKR_OK )
			break;

		if ( ( rv == CKR_PIN_INVALID ) || ( rv == CKR_PIN_LEN_RANGE ) )
			logError( TOKEN_INVALID_PIN );
		else
			goto done;

		shredPasswd( pszNewUserPin );
	}

	rc = 0;

done:
	free( pszReply );
	shredPasswd( pszSoPin );
	shredPasswd( pszNewSoPin );
	shredPasswd( pszNewUserPin );

	if ( hSession )
		closeTokenSession( hSession );

	closeToken( );

out:
	if ( rc == 0 )
		logInfo( TOKEN_CMD_SUCCESS, a_pszArgv[ 0 ] );
	else
		logInfo( TOKEN_CMD_FAILED, a_pszArgv[ 0 ] );

	return rc;
}
