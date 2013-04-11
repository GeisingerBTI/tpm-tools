/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2013 International Business
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

#include <limits.h>
#include <arpa/inet.h>

#include "tpm_tspi.h"
#include "tpm_utils.h"
#include "tpm_nvcommon.h"

#define BUFFER_SIZE 1024

static const char *ownerpass;
TSS_HCONTEXT hContext = 0;
static BOOL askOwnerPass = 1;
static BOOL ownerWellKnown = FALSE;
int opswd_len = -1;

static int parse(const int aOpt, const char *aArg)
{
	switch (aOpt) {
	case 'o':
		ownerpass = aArg;
		if (!ownerpass)
			askOwnerPass = TRUE;
		else
			askOwnerPass = FALSE;
		break;

	case 'y':
		ownerWellKnown = TRUE;
		ownerpass = NULL;
		askOwnerPass = FALSE;
		break;

	case 'u':
		useUnicode = TRUE;
		break;

	default:
		return -1;
	}
	return 0;
}


static void help(const char* aCmd)
{
	logCmdHelp(aCmd);
	logUnicodeCmdOption();
	logCmdOption("-y, --owner-well-known",
		     _("Use 20 bytes of zeros (TSS_WELL_KNOWN_SECRET) as the "
		       "TPM owner secret"));
	logCmdOption("-o <pass>, --pwdo=<pass>",
		     _("Owner password"));
}

const char *bool_to_str(int b)
{
	return b ? "TRUE" : "FALSE";
}

void Decode_copy_UINT32(uint32_t *out,unsigned char **blob)
{
	*out = Decode_UINT32((BYTE *)*blob);
	*blob += sizeof(*out);
}

TSS_RESULT
display_flags(void)
{
	TSS_HPOLICY htpmpolicy = 0;
	TSS_HCONTEXT hcontext = 0;
	TSS_HTPM htpm = 0;
	BYTE well_known_secret[] = TSS_WELL_KNOWN_SECRET;

	uint32_t i;
	uint32_t subcap = 0;
	uint32_t datasize = 0;
	unsigned char *pbuf;
	uint32_t  perm_flags;
	uint32_t stclear_flags;

	if (contextCreate(&hcontext) != TSS_SUCCESS)
		goto out_close;

	if (contextConnect(hcontext) != TSS_SUCCESS)
		goto out_close;

	if (contextGetTpm(hcontext, &htpm) != TSS_SUCCESS)
		goto out_close;

	if (policyGet(htpm, &htpmpolicy) != TSS_SUCCESS)
		goto out_close;

	if (ownerpass) {
		if (opswd_len < 0)
			opswd_len = strlen(ownerpass);

		if (policySetSecret(htpmpolicy, opswd_len,
					(BYTE *)ownerpass) != TSS_SUCCESS)
			goto out_close;
	} else {
		if (policySetSecret(htpmpolicy, TCPA_SHA1_160_HASH_LEN,
					(BYTE *)well_known_secret) != TSS_SUCCESS)
			goto out_close;
	}

	if (getCapability(htpm, TSS_TPMCAP_FLAG, 4, (unsigned char *)&subcap,
	              &datasize, &pbuf) != TSS_SUCCESS) {
		logMsg(_("error getting TPM_PERMANENT_FLAGS.\n"));
		goto out_close;
	}

	if (datasize != 2 * sizeof(uint32_t)) {
		logMsg(_("error getting TPM_PERMANENT_FLAGS, unexpected data size\n"));
		goto out_close;
	}

	if (pbuf == NULL) {
		logMsg(_("error getting TPM_PERMANENT_FLAGS, invalid data\n"));
		goto out_close;
	}

	logMsg("Status data:\n");
	for (i = 0; i < datasize; i++) {
		logMsg("%02x ", pbuf[i]);

		if (i % 16 == 15)
			logMsg("\n");
	}
	logMsg("\n");

	Decode_copy_UINT32(&perm_flags, &pbuf);
	Decode_copy_UINT32(&stclear_flags, &pbuf);

	/* slide flags left 1 bit to make parsing below easier */
	perm_flags = perm_flags << 1;
	stclear_flags = stclear_flags << 1;

	logMsg("TPM_PERMANENT_FLAGS:\n");
	logMsg("\t disable: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_DISABLE)));
	logMsg("\t ownership: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_OWNERSHIP)));
	logMsg("\t deactivated: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_DEACTIVATED)));
	logMsg("\t readPubek: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_READPUBEK)));
	logMsg("\t disableOwnerClear: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_DISABLEOWNERCLEAR)));
	logMsg("\t allowMaintenance: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_ALLOWMAINTENANCE)));
	logMsg("\t physicalPresenceLifetimeLock: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_PHYSICALPRESENCELIFETIMELOCK)));
	logMsg("\t physicalPresenceHWEnable: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_PHYSICALPRESENCEHWENABLE)));
	logMsg("\t physicalPresenceCMDEnable: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_PHYSICALPRESENCECMDENABLE)));
	logMsg("\t CEKPUsed: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_CEKPUSED)));
	logMsg("\t TPMpost: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_TPMPOST)));
	logMsg("\t TPMpostLock: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_TPMPOSTLOCK)));
	logMsg("\t FIPS: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_FIPS)));
	logMsg("\t Operator: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_OPERATOR)));
	logMsg("\t enableRevokeEK: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_ENABLEREVOKEEK)));
	logMsg("\t nvLocked: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_NV_LOCKED)));
	logMsg("\t readSRKPub: %s\n",
			   bool_to_str(perm_flags & (1 << TPM_PF_READSRKPUB)));
	logMsg("\t tpmEstablished: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_RESETESTABLISHMENTBIT)));
	logMsg("\t maintenanceDone: %s\n",
	           bool_to_str(perm_flags & (1 << TPM_PF_MAINTENANCEDONE)));

	logMsg("\nTPM_STCLEAR_FLAGS:\n");
	logMsg("\t deactivated: %s\n",
			   bool_to_str(stclear_flags & (1 << TPM_SF_DEACTIVATED)));
	logMsg("\t disableForceClear: %s\n",
	           bool_to_str(stclear_flags & (1 << TPM_SF_DISABLEFORCECLEAR)));
	logMsg("\t physicalPresence: %s\n",
	           bool_to_str(stclear_flags & (1 << TPM_SF_PHYSICALPRESENCE)));
	logMsg("\t physicalPresenceLock: %s\n",
	           bool_to_str(stclear_flags & (1 << TPM_SF_PHYSICALPRESENCELOCK)));
	logMsg("\t bGlobalLock: %s\n",
			   bool_to_str(stclear_flags & (1 << TPM_SF_GLOBALLOCK)));

out_close:
	contextClose(hcontext);

	return TSS_SUCCESS;
}

int main(int argc, char **argv)
{
	int iRc = -1;
	struct option hOpts[] = {
		{"pwdo"            , optional_argument, NULL, 'o'},
		{"owner-well-known",       no_argument, NULL, 'y'},
		{"use-unicode"     ,       no_argument, NULL, 'u'},
	};

	initIntlSys();

	if (genericOptHandler
		    (argc, argv, "uyo:", hOpts,
		     sizeof(hOpts) / sizeof(struct option), parse, help) != 0)
		goto out;

	if (askOwnerPass) {
		ownerpass = _GETPASSWD(_("Enter owner password: "), &opswd_len,
			FALSE, useUnicode );
		if (!ownerpass) {
			logError(_("Failed to get owner password\n"));
			goto out;
		}
	}

	if (display_flags() != TSS_SUCCESS)
		return iRc;

	iRc = 0;

       out:

	return iRc;
}
