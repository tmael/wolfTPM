/* tpm2_wrap.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef __TPM2_WRAP_H__
#define __TPM2_WRAP_H__

#include <wolftpm/tpm2.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFTPM2_HANDLE {
    TPM_HANDLE      hndl;
    TPM2B_AUTH      auth;
    TPMT_SYM_DEF    symmetric;
    TPM2B_NAME      name;

    /* bit-fields */
    unsigned int    policyPass : 1;
    unsigned int    policyAuth : 1; /* Handle requires policy auth */
    unsigned int    nameLoaded : 1; /* flag to indicate if "name" was loaded and computed */
} WOLFTPM2_HANDLE;

#define TPM_SES_PWD 0xFF /* Session type for Password that fits in one byte */

typedef struct WOLFTPM2_SESSION {
    TPM_ST          type;         /* Trial, Policy or HMAC; or TPM_SES_PWD */
    WOLFTPM2_HANDLE handle;       /* Session handle from StartAuthSession */
    TPM2B_NONCE     nonceTPM;     /* Value from StartAuthSession */
    TPM2B_NONCE     nonceCaller;  /* Fresh nonce at each command */
    TPM2B_DIGEST    salt;         /* User defined */
    TPMI_ALG_HASH   authHash;
    TPMA_SESSION    sessionAttributes;
    TPM2B_AUTH*     bind;         /* pointer to bind auth password */
} WOLFTPM2_SESSION;

typedef struct WOLFTPM2_DEV {
    TPM2_CTX ctx;
    TPM2_AUTH_SESSION session[MAX_SESSION_NUM];
} WOLFTPM2_DEV;

/* Public Key with Handle.
 *   Must have "handle" and "pub" as first members */
typedef struct WOLFTPM2_KEY {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;
} WOLFTPM2_KEY;

/* Primary Key - From TPM2_CreatePrimary that include creation hash and ticket.
 * WOLFTPM2_PKEY can be cast to WOLFTPM2_KEY.
 *   Must have "handle" and "pub" as first members */
typedef struct WOLFTPM2_PKEY {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;

    TPM2B_DIGEST      creationHash;
    TPMT_TK_CREATION  creationTicket;
} WOLFTPM2_PKEY;

/* Private/Public Key:
 * WOLFTPM2_KEYBLOB can be cast to WOLFTPM2_KEY
 * Must have "handle" and "pub" as first members */
typedef struct WOLFTPM2_KEYBLOB {
    WOLFTPM2_HANDLE   handle;
    TPM2B_PUBLIC      pub;
    TPM2B_PRIVATE     priv;
    /* Note: Member "name" moved to "handle.name" */
} WOLFTPM2_KEYBLOB;

typedef struct WOLFTPM2_HASH {
    WOLFTPM2_HANDLE handle;
} WOLFTPM2_HASH;

typedef struct WOLFTPM2_NV {
    WOLFTPM2_HANDLE handle;
    TPMA_NV attributes;
} WOLFTPM2_NV;


typedef enum WOLFTPM2_MFG {
    TPM_MFG_UNKNOWN = 0,
    TPM_MFG_INFINEON,
    TPM_MFG_STM,
    TPM_MFG_MCHP,
    TPM_MFG_NUVOTON,
    TPM_MFG_NATIONTECH,
} WOLFTPM2_MFG;

typedef struct WOLFTPM2_CAPS {
    WOLFTPM2_MFG mfg;
    char mfgStr[4 + 1];
    char vendorStr[(4 * 4) + 1];
    word32 tpmType;
    word16 fwVerMajor;
    word16 fwVerMinor;
    word32 fwVerVendor;

    /* bits */
    word16 fips140_2 : 1; /* using FIPS mode */
    word16 cc_eal4   : 1; /* Common Criteria EAL4+ */
    word16 req_wait_state : 1; /* requires SPI wait state */
} WOLFTPM2_CAPS;


/* Wrapper API's to simplify TPM use */

/** @defgroup wolfTPM2_Wrappers wolfTPM2 Wrappers
 *
 * This module describes the rich API of wolfTPM called wrappers.
 *
 * wolfTPM wrappers are used in two main cases:
 * * Perform common TPM 2.0 tasks, like key generation and storage
 * * Perform complex TPM 2.0 tasks, like attestation and parameter encryption
 *
 * wolfTPM enables quick and rapid use of TPM 2.0 thanks to its many wrapper functions.
 *
 */

/* For devtpm and swtpm builds, the ioCb and userCtx are not used and should be set to NULL */

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Test initialization of a TPM and optionally the TPM capabilities can be received

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)
    \param caps to a structure of WOLFTPM2_CAPS type for returning the TPM capabilities (can be NULL)

    \sa wolfTPM2_Init
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Test(TPM2HalIoCb ioCb, void* userCtx, WOLFTPM2_CAPS* caps);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Complete initialization of a TPM

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to an empty structure of WOLFTPM2_DEV type
    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)

    _Example_
    \code
    int rc;
    WOLFTPM2_DEV dev;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_Init failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Init(WOLFTPM2_DEV* dev, TPM2HalIoCb ioCb, void* userCtx);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Use an already initialized TPM, in its current TPM locality

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to an empty structure of WOLFTPM2_DEV type
    \param ioCb function pointer to a IO callback (see hal/tpm_io.h)
    \param userCtx pointer to a user context (can be NULL)

    \sa wolfTPM2_Init
    \sa wolfTPM2_Cleanup
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Cleanup(WOLFTPM2_DEV* dev);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deinitialization of a TPM (and wolfcrypt if it was used)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type
    \param doShutdown flag value, if true a TPM2_Shutdown command will be executed

    _Example_
    \code
    int rc;

    //perform TPM2_Shutdown after deinitialization
    rc = wolfTPM2_Cleanup_ex(&dev, 1);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_Cleanup_ex failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_OpenExisting
    \sa wolfTPM2_Test
    \sa TPM2_Init
*/
WOLFTPM_API int wolfTPM2_Cleanup_ex(WOLFTPM2_DEV* dev, int doShutdown);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reports the available TPM capabilities

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a populated structure of WOLFTPM2_DEV type
    \param caps pointer to an empty structure of WOLFTPM2_CAPS type to store the capabilities

    _Example_
    \code
    int rc;
    WOLFTPM2_CAPS caps;

    //perform TPM2_Shutdown after deinitialization
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc != TPM_RC_SUCCESS) {
        //wolfTPM2_GetCapabilities failed
        goto exit;
    }
    \endcode

    \sa wolfTPM2_GetTpmDevId
    \sa wolfTPM2_SelfTest
    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_GetCapabilities(WOLFTPM2_DEV* dev, WOLFTPM2_CAPS* caps);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Gets a list of handles

    \return 0 or greater: successful, count of handles
    \return TPM_RC_FAILURE: generic failure (check TPM IO communication and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param handle handle to start from (example: PCR_FIRST, NV_INDEX_FIRST,
        HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, PERMANENT_FIRST,
        TRANSIENT_FIRST or PERSISTENT_FIRST)
    \param handles pointer to TPML_HANDLE to return handle results (optional)

    _Example_
    \code
    int persistent_handle_count;

    // get count of persistent handles
    persistent_handle_count = wolfTPM2_GetHandles(PERSISTENT_FIRST, NULL);
    \endcode

    \sa wolfTPM2_GetCapabilities
*/
WOLFTPM_API int wolfTPM2_GetHandles(TPM_HANDLE handle, TPML_HANDLE* handles);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Clears one of the TPM Authorization slots, pointed by its index number

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: unable to get lock on the TPM2 Context
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_UnsetAuth(WOLFTPM2_DEV* dev, int index);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Clears one of the TPM Authorization session slots, pointed by its index
    number and saves the nonce from the TPM so the session can continue to be used
    again with wolfTPM2_SetAuthSession

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: unable to get lock on the TPM2 Context
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param session pointer to a WOLFTPM2_SESSION struct used with wolfTPM2_StartSession and wolfTPM2_SetAuthSession

    \sa wolfTPM2_StartSession
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_UnsetAuthSession(WOLFTPM2_DEV* dev, int index, WOLFTPM2_SESSION* session);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided index, session handle, attributes and auth
    \note It is recommended to use one of the other wolfTPM2 wrappers, like wolfTPM2_SetAuthPassword.
    Because the wolfTPM2_SetAuth wrapper provides complete control over the TPM Authorization slot for
    advanced use cases. In most scenarios, wolfTPM2_SetAuthHandle and SetAuthPassword are used.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param sessionHandle integer value of TPM_HANDLE type
    \param auth pointer to a structure of type TPM2B_AUTH containing one TPM Authorization
    \param sessionAttributes integer value of type TPMA_SESSION, selecting one or more attributes for the Session
    \param name pointer to a TPM2B_NAME structure

    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetAuth(WOLFTPM2_DEV* dev, int index,
    TPM_HANDLE sessionHandle, const TPM2B_AUTH* auth, TPMA_SESSION sessionAttributes,
    const TPM2B_NAME* name);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided user auth, typically a password
    \note Often used for authorizing the loading and use of TPM keys, including Primary Keys

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param auth pointer to a structure of type TPM2B_AUTH, typically containing a TPM Key Auth

    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
    \sa wolfTPM2_SetAuth
*/

WOLFTPM_API int wolfTPM2_SetAuthPassword(WOLFTPM2_DEV* dev, int index, const TPM2B_AUTH* auth);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the user auth associated with a wolfTPM2 Handle
    \note This wrapper is especially useful when using a TPM key for multiple operations and TPM Authorization is required again.

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param handle pointer to a populated structure of WOLFTPM2_HANDLE type

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/

WOLFTPM_API int wolfTPM2_SetAuthHandle(WOLFTPM2_DEV* dev, int index, const WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Sets a TPM Authorization slot using the provided wolfTPM2 session object
    \note This wrapper is useful for configuring TPM sessions, e.g. session for parameter encryption

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param tpmSession pointer to a WOLFTPM2_SESSION struct used with wolfTPM2_StartSession and wolfTPM2_SetAuthSession

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetSessionHandle(WOLFTPM2_DEV* dev, int index,
    WOLFTPM2_SESSION* tpmSession);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Updates the Name used in a TPM Session with the Name associated with wolfTPM2 Handle
    \note Typically, this wrapper is used from another wrappers and in very specific use cases. For example, wolfTPM2_NVWriteAuth

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param index integer value, specifying the TPM Authorization slot, between zero and three
    \param handle pointer to a populated structure of WOLFTPM2_HANDLE type

    \sa wolfTPM2_SetAuth
    \sa wolfTPM2_SetAuthPassword
    \sa wolfTPM2_SetAuthHandle
    \sa wolfTPM2_SetAuthSession
*/
WOLFTPM_API int wolfTPM2_SetAuthHandleName(WOLFTPM2_DEV* dev, int index, const WOLFTPM2_HANDLE* handle);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to prepare and create a TPM 2.0 Primary Key
    \note TPM 2.0 allows only asymmetric RSA or ECC primary keys. Afterwards, both symmetric and asymmetric keys can be created under a TPM 2.0 Primary Key
    Typically, Primary Keys are used to create Hierarchies of TPM 2.0 Keys.
    The TPM uses a Primary Key to wrap the other keys, signing or decrypting.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param primaryHandle integer value, specifying one of four TPM 2.0 Primary Seeds: TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization for the Primary Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_CreatePrimaryKey_ex
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_CreatePrimaryKey(WOLFTPM2_DEV* dev,
    WOLFTPM2_KEY* key, TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Single function to prepare and create a TPM 2.0 Primary Key
    \note TPM 2.0 allows only asymmetric RSA or ECC primary keys. Afterwards, both symmetric and asymmetric keys can be created under a TPM 2.0 Primary Key
    Typically, Primary Keys are used to create Hierarchies of TPM 2.0 Keys.
    The TPM uses a Primary Key to wrap the other keys, signing or decrypting.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pkey pointer to an empty struct of WOLFTPM2_PKEY type including the creation hash and ticket.
    \param primaryHandle integer value, specifying one of four TPM 2.0 Primary Seeds: TPM_RH_OWNER, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM or TPM_RH_NULL
    \param publicTemplate pointer to a TPMT_PUBLIC structure populated manually or using one of the wolfTPM2_GetKeyTemplate_... wrappers
    \param auth pointer to a string constant, specifying the password authorization for the Primary Key
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_CreateKey
    \sa wolfTPM2_CreatePrimaryKey
    \sa wolfTPM2_GetKeyTemplate_RSA
    \sa wolfTPM2_GetKeyTemplate_ECC
*/
WOLFTPM_API int wolfTPM2_CreatePrimaryKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_PKEY* pkey,
    TPM_HANDLE primaryHandle, TPMT_PUBLIC* publicTemplate,
    const byte* auth, int authSz);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Wrapper to load the public part of an external key
    \note The key must be formatted to the format expected by the TPM, see the 'pub' argument and the alternative wrappers.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty struct of WOLFTPM2_KEY type
    \param pub pointer to a populated structure of TPM2B_PUBLIC type

    \sa wolfTPM2_LoadRsaPublicKey
    \sa wolfTPM2_LoadEccPublicKey
    \sa wolfTPM2_wolfTPM2_LoadPrivateKey
*/
WOLFTPM_API int wolfTPM2_LoadPublicKey(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub);

/* Same as wolfTPM2_LoadPublicKey, but adds hierarchy option (default is owner) */
WOLFTPM_API int wolfTPM2_LoadPublicKey_ex(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    const TPM2B_PUBLIC* pub, TPM_HANDLE hierarchy);



/*!
    \ingroup wolfTPM2_Wrappers
    \brief Perform RSA encryption using a TPM 2.0 key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param padScheme integer value of TPM_ALG_ID type, specifying the padding scheme
    \param msg pointer to a byte buffer, containing the arbitrary data for encryption
    \param msgSz integer value, specifying the size of the arbitrary data buffer
    \param out pointer to a byte buffer, where the encrypted data will be stored
    \param outSz integer value, specifying the size of the encrypted data buffer

    \sa wolfTPM2_RsaDecrypt
*/
WOLFTPM_API int wolfTPM2_RsaEncrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* msg, int msgSz, byte* out, int* outSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Perform RSA decryption using a TPM 2.0 key

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to a struct of WOLFTPM2_KEY type, holding a TPM key material
    \param padScheme integer value of TPM_ALG_ID type, specifying the padding scheme
    \param in pointer to a byte buffer, containing the encrypted data
    \param inSz integer value, specifying the size of the encrypted data buffer
    \param msg pointer to a byte buffer, containing the decrypted data
    \param[in,out] msgSz pointer to size of the encrypted data buffer, on return set actual size

    \sa wolfTPM2_RsaEncrypt
*/
WOLFTPM_API int wolfTPM2_RsaDecrypt(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
    TPM_ALG_ID padScheme, const byte* in, int inSz, byte* msg, int* msgSz);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Read the values of a specified TPM 2.0 Platform Configuration Registers(PCR)
    \note Make sure to specify the correct hashing algorithm, because there are two sets of PCR registers, one for SHA256 and the other for SHA1(deprecated, but still possible to be read)

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrIndex integer value, specifying a valid PCR index, between 0 and 23 (TPM locality could have an impact on successful access)
    \param hashAlg integer value, specifying a TPM_ALG_SHA256 or TPM_ALG_SHA1 registers to be accessed
    \param digest pointer to a byte buffer, where the PCR values will be stored
    \param[in,out] pDigestLen pointer to an integer variable, where the size of the digest buffer will be stored

    \sa wolfTPM2_ExtendPCR
*/
WOLFTPM_API int wolfTPM2_ReadPCR(WOLFTPM2_DEV* dev,
    int pcrIndex, int hashAlg, byte* digest, int* pDigestLen);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reset a PCR register to its default value
    \note Only PCR registers 0-15 can be reset, and this operation requires platform authorization

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrIndex integer value, specifying a valid PCR index between 0 and 15

    \sa wolfTPM2_ReadPCR
    \sa wolfTPM2_ExtendPCR
*/
WOLFTPM_API int wolfTPM2_ResetPCR(WOLFTPM2_DEV* dev, int pcrIndex);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extend a PCR register with a user provided digest
    \note Make sure to specify the correct hashing algorithm

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param pcrIndex integer value, specifying a valid PCR index, between 0 and 23 (TPM locality could have an impact on successful access)
    \param hashAlg integer value, specifying a TPM_ALG_SHA256 or TPM_ALG_SHA1 registers to be accessed
    \param digest pointer to a byte buffer, containing the digest value to be extended into the PCR
    \param digestLen the size of the digest buffer

    \sa wolfTPM2_ReadPCR
*/
WOLFTPM_API int wolfTPM2_ExtendPCR(WOLFTPM2_DEV* dev, int pcrIndex, int hashAlg,
    const byte* digest, int digestLen);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reads user data from a NV Index, starting at the given offset
    \note User data size should be less or equal to the NV Index maxSize specified using wolfTPM2_CreateAuth

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to a populated structure of WOLFTPM2_NV type
    \param nvIndex integer value, holding an existing NV Index Handle value
    \param dataBuf pointer to an empty byte buffer, used to store the read data from the TPM's NVRAM
    \param pDataSz pointer to an integer variable, used to store the size of the data read from NVRAM, in bytes
    \param offset integer value of word32 type, specifying the offset from the NV Index memory start, can be zero

    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
    \sa wolfTPM2_NVReadAuthPolicy
*/
WOLFTPM_API int wolfTPM2_NVReadAuth(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Reads user data from a NV Index, starting at the given offset. Allows using a policy session and PCR's for authentication.
    \note User data size should be less or equal to the NV Index maxSize specified using wolfTPM2_CreateAuth

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param tpmSession pointer to a WOLFTPM2_SESSION struct used with wolfTPM2_StartSession and wolfTPM2_SetAuthSession
    \param pcrAlg the hash algorithm to use with PCR policy
    \param pcrArray array of PCR Indexes to use when creating the policy
    \param pcrArraySz the number of PCR Indexes in the pcrArray
    \param nv pointer to a populated structure of WOLFTPM2_NV type
    \param nvIndex integer value, holding an existing NV Index Handle value
    \param dataBuf pointer to an empty byte buffer, used to store the read data from the TPM's NVRAM
    \param pDataSz pointer to an integer variable, used to store the size of the data read from NVRAM, in bytes
    \param offset integer value of word32 type, specifying the offset from the NV Index memory start, can be zero

    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVReadAuthPolicy(WOLFTPM2_DEV* dev, WOLFTPM2_SESSION* tpmSession,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz, WOLFTPM2_NV* nv,
    word32 nvIndex, byte* dataBuf, word32* pDataSz, word32 offset);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Open an NV and populate the required authentication and name hash.

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nv pointer to an empty structure of WOLFTPM2_NV type, to hold the new NV Index
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success
    \param auth pointer to a string constant, specifying the password authorization for this NV Index
    \param authSz integer value, specifying the size of the password authorization, in bytes

    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_UnloadHandle
*/
WOLFTPM_API int wolfTPM2_NVOpen(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 nvIndex, const byte* auth, word32 authSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVRead(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex, byte* dataBuf, word32* dataSz, word32 offset);
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Deprecated, use newer API

    \sa wolfTPM2_NVDeleteAuth
*/
WOLFTPM_API int wolfTPM2_NVDelete(WOLFTPM2_DEV* dev, TPM_HANDLE authHandle,
    word32 nvIndex);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Extracts the public information about an nvIndex, such as maximum size

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param nvIndex integer value, holding the NV Index Handle given by the TPM upon success
    \param nvPublic pointer to a TPMS_NV_PUBLIC, used to store the extracted nvIndex public information

    \sa wolfTPM2_NVCreateAuth
    \sa wolfTPM2_NVDeleteAuth
    \sa wolfTPM2_NVWriteAuth
    \sa wolfTPM2_NVReadAuth
*/
WOLFTPM_API int wolfTPM2_NVReadPublic(WOLFTPM2_DEV* dev, word32 nvIndex,
    TPMS_NV_PUBLIC* nvPublic);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Use to discard any TPM loaded object

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param handle pointer to a structure of WOLFTPM2_HANDLE type, with a valid TPM 2.0 handle value

    \sa wolfTPM2_Clear
*/
WOLFTPM_API int wolfTPM2_UnloadHandle(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* handle);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper function to start a TPM generated hash

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param hashAlg integer value, specifying a valid TPM 2.0 hash algorithm
    \param usageAuth pointer to a string constant, specifying the authorization for subsequent use of the hash
    \param usageAuthSz integer value, specifying the size of the authorization, in bytes

    \sa wolfTPM2_HashUpdate
    \sa wolfTPM2_HashFinish
*/
WOLFTPM_API int wolfTPM2_HashStart(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    TPMI_ALG_HASH hashAlg, const byte* usageAuth, word32 usageAuthSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Update a TPM generated hash with new user data
    \note Make sure the auth is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param data pointer to a byte buffer, containing the user data to be added to the hash
    \param dataSz integer value of word32 type, specifying the size of the user data, in bytes

    \sa wolfTPM2_HashStart
    \sa wolfTPM2_HashFinish
*/
WOLFTPM_API int wolfTPM2_HashUpdate(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    const byte* data, word32 dataSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Finalize a TPM generated hash and get the digest output in a user buffer
    \note Make sure the auth is correctly set

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param hash pointer to a WOLFTPM2_HASH structure
    \param digest pointer to a byte buffer, used to store the resulting digest
    \param[in,out] digestSz pointer to size of digest buffer, on return set to bytes stored in digest buffer

    \sa wolfTPM2_HashStart
    \sa wolfTPM2_HashUpdate
*/
WOLFTPM_API int wolfTPM2_HashFinish(WOLFTPM2_DEV* dev, WOLFTPM2_HASH* hash,
    byte* digest, word32* digestSz);

/*!
    \ingroup wolfTPM2_Wrappers
    \brief Creates and loads a new TPM key of KeyedHash type, typically used for HMAC operations
    \note To generate HMAC using the TPM it is recommended to use the wolfTPM2_Hmac wrappers

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param key pointer to an empty structure of WOLFTPM2_KEY type, to store the generated key
    \param parent pointer to a structure of WOLFTPM2_KEY type, containing a valid TPM handle of a primary key
    \param hashAlg integer value, specifying a valid TPM 2.0 hash algorithm
    \param keyBuf pointer to a byte array, containing derivation values for the new KeyedHash key
    \param keySz integer value, specifying the size of the derivation values stored in keyBuf, in bytes
    \param usageAuth pointer to a string constant, specifying the authorization of the new key
    \param usageAuthSz integer value, specifying the size of the authorization, in bytes

    \sa wolfTPM2_HmacStart
    \sa wolfTPM2_HmacUpdate
    \sa wolfTPM2_HmacFinish
*/

/*!
    \ingroup wolfTPM2_Wrappers
    \brief One-shot API to unload subsequent TPM handles

    \return TPM_RC_SUCCESS: successful
    \return TPM_RC_FAILURE: generic failure (check TPM IO and TPM return code)
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param handleStart integer value of word32 type, specifying the value of the first TPM handle
    \param handleCount integer value of word32 type, specifying the number of handles

    \sa wolfTPM2_Init
*/
WOLFTPM_API int wolfTPM2_UnloadHandles(WOLFTPM2_DEV* dev, word32 handleStart,
    word32 handleCount);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Prepares a TPM public template for generating the TPM Endorsement Key

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template
    \param alg can be only TPM_ALG_RSA or TPM_ALG_ECC, see Note above
    \param keyBits integer value, specifying bits for the key, typically 2048 (RSA) or 256 (ECC)
    \param curveID use one of the accepted TPM_ECC_CURVE values like TPM_ECC_NIST_P256 (only used when alg=TPM_ALG_ECC)
    \param nameAlg integer value of TPMI_ALG_HASH type, specifying a valid TPM2 hashing algorithm (typically TPM_ALG_SHA256)
    \param highRange integer value: 0=low range, 1=high range

    \sa wolfTPM2_GetKeyTemplate_ECC_EK
    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
    \sa wolfTPM2_GetKeyTemplate_EKIndex
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_EK(TPMT_PUBLIC* publicTemplate, TPM_ALG_ID alg,
    int keyBits, TPM_ECC_CURVE curveID, TPM_ALG_ID nameAlg, int highRange);


/*!
    \ingroup wolfTPM2_Wrappers
    \brief Helper to get the Endorsement public key template by NV index

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param nvIndex handle for NV index. Typically starting from TPM_20_TCG_NV_SPACE
    \param publicTemplate pointer to an empty structure of TPMT_PUBLIC type, to store the new template

    \sa wolfTPM2_GetKeyTemplate_EK
    \sa wolfTPM2_GetKeyTemplate_ECC_EK
    \sa wolfTPM2_GetKeyTemplate_RSA_SRK
    \sa wolfTPM2_GetKeyTemplate_RSA_AIK
*/
WOLFTPM_API int wolfTPM2_GetKeyTemplate_EKIndex(word32 nvIndex,
    TPMT_PUBLIC* publicTemplate);
/* moved to tpm.h native code. macros here for backwards compatibility */
#define wolfTPM2_SetupPCRSel  TPM2_SetupPCRSel



/*!
    \ingroup wolfTPM2_Wrappers

    \brief Apply the PCR's to the policy digest for the policy session.

    \return TPM_RC_SUCCESS: successful
    \return INPUT_SIZE_E: policyDigestSz is too small to hold the returned digest
    \return BAD_FUNC_ARG: check the provided arguments

    \param dev pointer to a TPM2_DEV struct
    \param sessionHandle the handle of the current policy session, a session is required to use policy PCR
    \param pcrAlg the hash algorithm to use with PCR policy
    \param pcrArray array of PCR Indexes to use when creating the policy
    \param pcrArraySz the number of PCR Indexes in the pcrArray

    \sa wolfTPM2_GetPolicyDigest
    \sa wolfTPM2_PolicyPCR
    \sa wolfTPM2_PolicyAuthorize
    \sa wolfTPM2_PolicyRestart
*/
WOLFTPM_API int wolfTPM2_PolicyPCR(WOLFTPM2_DEV* dev, TPM_HANDLE sessionHandle,
    TPM_ALG_ID pcrAlg, byte* pcrArray, word32 pcrArraySz);



/* Internal API's */
/*!
    \ingroup wolfTPM2_Wrappers
    \brief Internal helper to create RSA key template
    \note Used internally by key creation functions

    \return TPM_RC_SUCCESS: successful
    \return BAD_FUNC_ARG: check the provided arguments

    \param publicTemplate pointer to TPMT_PUBLIC template to populate
    \param nameAlg hash algorithm for key name
    \param objectAttributes TPM object attributes
    \param keyBits RSA key size in bits
    \param exponent RSA public exponent
    \param sigScheme signature scheme algorithm
    \param sigHash hash algorithm for signatures

    \sa GetKeyTemplateECC
*/
WOLFTPM_LOCAL int GetKeyTemplateRSA(TPMT_PUBLIC* publicTemplate,
    TPM_ALG_ID nameAlg, TPMA_OBJECT objectAttributes, int keyBits, long exponent,
    TPM_ALG_ID sigScheme, TPM_ALG_ID sigHash);



#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* __TPM2_WRAP_H__ */
