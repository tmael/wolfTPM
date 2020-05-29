/* signed_timestamp.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* This example shows how to use extended authorization sessions (TPM2.0) and
 * generate a signed timestamp from the TPM using a Attestation Identity Key.
 */

#include <wolftpm/tpm2_wrap.h>

#include <examples/timestamp/signed_timestamp.h>
#include <examples/tpm_io.h>
#include <examples/tpm_test.h>

#include <stdio.h>


/******************************************************************************/
/* --- BEGIN TPM Timestamp Test -- */
/******************************************************************************/

int TPM2_Timestamp_Test(void* userCtx)
{
    int rc;
    WOLFTPM2_DEV dev;
    TPMS_TIME_ATTEST_INFO* attestedTime = NULL;

    union {
        GetTime_In getTime;
        /* For managing TPM session */
        StartAuthSession_In authSes;
        PolicySecret_In policySecret;
        /* For removing keys after use */
        FlushContext_In flushCtx;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        ReadClock_Out readClock;
        GetTime_Out getTime;
        /* Output from session operations */
        StartAuthSession_Out authSes;
        PolicySecret_Out policySecret;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;

    TPM_HANDLE sessionHandle = TPM_RH_NULL;

    WOLFTPM2_KEY endorse = { .handle.hndl = TPM_RH_NULL }; /* EK  */
    WOLFTPM2_KEY storage = { .handle.hndl = TPM_RH_NULL }; /* SRK */
    WOLFTPM2_KEY rsaKey = { .handle.hndl = TPM_RH_NULL };  /* AIK */

    const byte storagePwd[] = "WolfTPMpassword";
    const byte usageAuth[] = "ThisIsASecretUsageAuth";

    TPMS_AUTH_COMMAND session[MAX_SESSION_NUM];


    printf("TPM2 Demo of generating signed timestamp from the TPM\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }


    /* Define the default session auth that has NULL password */
    XMEMSET(session, 0, sizeof(session));
    session[0].sessionHandle = TPM_RS_PW;
    session[0].auth.size = 0; /* NULL Password */
    TPM2_SetSessionAuth(session);


    /* ReadClock for quick test of the TPM communication */
    XMEMSET(&cmdOut.readClock, 0, sizeof(cmdOut.readClock));
    rc = TPM2_ReadClock(&cmdOut.readClock);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_ReadClock failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_ReadClock: success\n");


    /* Create Endorsement Key, also called EK */
    rc = wolfTPM2_CreateEK(&dev, &endorse, TPM_ALG_RSA);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreateEK: Endorsement failed 0x%x: %s\n",
            rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_CreateEK: Endorsement 0x%x (%d bytes)\n",
        (word32)endorse.handle.hndl, endorse.pub.size);


    /* Create Storage Key, also called SRK */
    rc = wolfTPM2_CreateSRK(&dev, &storage, TPM_ALG_RSA, storagePwd,
        sizeof(storagePwd)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_CreatePrimary: Storage failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_CreatePrimary: Storage 0x%x (%d bytes)\n",
        (word32)storage.handle.hndl, storage.pub.size);


    /* Start Auth Session */
    XMEMSET(&cmdIn.authSes, 0, sizeof(cmdIn.authSes));
    cmdIn.authSes.sessionType = TPM_SE_POLICY;
    cmdIn.authSes.tpmKey = TPM_RH_NULL;
    cmdIn.authSes.bind = TPM_RH_NULL;
    cmdIn.authSes.symmetric.algorithm = TPM_ALG_NULL;
    cmdIn.authSes.authHash = TPM_ALG_SHA256;
    cmdIn.authSes.nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
    rc = TPM2_GetNonce(cmdIn.authSes.nonceCaller.buffer,
                       cmdIn.authSes.nonceCaller.size);
    if (rc < 0) {
        printf("TPM2_GetNonce failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    rc = TPM2_StartAuthSession(&cmdIn.authSes, &cmdOut.authSes);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_StartAuthSession failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    sessionHandle = cmdOut.authSes.sessionHandle;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n", (word32)sessionHandle);


    /* Set PolicySecret for our session to enable use of the Endorsement Hierarchy */
    XMEMSET(&cmdIn.policySecret, 0, sizeof(cmdIn.policySecret));
    cmdIn.policySecret.authHandle = TPM_RH_ENDORSEMENT;
    cmdIn.policySecret.policySession = sessionHandle;
    rc = TPM2_PolicySecret(&cmdIn.policySecret, &cmdOut.policySecret);
    if (rc != TPM_RC_SUCCESS) {
        printf("policySecret failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_policySecret success\n"); /* No use of the output */


    /* At this stage, the EK is created and NULL password has already been set
     * The EH is enabled through policySecret over the active TPM session and
     * the creation of Attestation Identity Key under the EH can take place.
     */


    /* set session auth for storage key */
    session[0].auth.size = sizeof(storagePwd)-1;
    XMEMCPY(session[0].auth.buffer, storagePwd, session[0].auth.size);


    /* Create an RSA key for Attestation purposes */
    rc = wolfTPM2_CreateAndLoadAIK(&dev, &rsaKey, TPM_ALG_RSA, &storage,
        usageAuth, sizeof(usageAuth)-1);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Create RSA failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }


    /* set NULL password auth for using EK */
    session[0].auth.size = 0;

    /* set auth for using the AIK */
    session[1].sessionHandle = TPM_RS_PW;
    session[1].auth.size = sizeof(usageAuth)-1;
    XMEMCPY(session[1].auth.buffer, usageAuth, session[1].auth.size);


    /* At this stage: The EK is created, AIK is created and loaded,
     * Endorsement Hierarchy is enabled through policySecret,
     * the use of the loaded AIK is enabled through its usageAuth.
     * Invoking attestation of the TPM time structure can take place.
     */

    /* GetTime */
    XMEMSET(&cmdIn.getTime, 0, sizeof(cmdIn.getTime));
    XMEMSET(&cmdOut.getTime, 0, sizeof(cmdOut.getTime));
    cmdIn.getTime.privacyAdminHandle = TPM_RH_ENDORSEMENT;
    /* TPM_RH_NULL is a valid handle for NULL signature */
    cmdIn.getTime.signHandle = rsaKey.handle.hndl;
    /* TPM_ALG_NULL is a valid handle for  NULL signature */
    cmdIn.getTime.inScheme.scheme = TPM_ALG_RSASSA;
    cmdIn.getTime.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    cmdIn.getTime.qualifyingData.size = 0; /* optional */
    rc = TPM2_GetTime(&cmdIn.getTime, &cmdOut.getTime);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTime failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }
    printf("TPM2_GetTime: success\n");
    /* Print result in human friendly way */
    attestedTime = (TPMS_TIME_ATTEST_INFO*)cmdOut.getTime.timeInfo.attestationData;
    printf("TPM2_GetTime: TPMS_TIME_ATTEST_INFO with signature attests:\n");
    printf("* TPM Uptime (in ms) since power-up = %lu\n", 
        (unsigned long)attestedTime->time.clockInfo.clock);

exit:

    /* Close session */
    if (sessionHandle != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = sessionHandle;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    /* Close key handles */
    if (rsaKey.handle.hndl != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = rsaKey.handle.hndl;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (endorse.handle.hndl != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = endorse.handle.hndl;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }
    if (storage.handle.hndl != TPM_RH_NULL) {
        cmdIn.flushCtx.flushHandle = storage.handle.hndl;
        TPM2_FlushContext(&cmdIn.flushCtx);
    }

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM Timestamp Test -- */
/******************************************************************************/


#ifndef NO_MAIN_DRIVER
int main(void)
{
    int rc;

    rc = TPM2_Timestamp_Test(NULL);

    return rc;
}
#endif
