/**
 * kyber_link.c — LibraryLink bridge for CRYSTAL-Kyber KEM
 *
 * Exposes three functions to Wolfram Language:
 *   kyber_keygen(securityLevel) → {publicKey, secretKey} as integer tensors
 *   kyber_encapsulate(publicKey, securityLevel) → {ciphertext, sharedSecret}
 *   kyber_decapsulate(ciphertext, secretKey, securityLevel) → sharedSecret
 *
 * Compiled with all three security levels (K=2,3,4) via KYBER_NAMESPACE
 * disambiguation — each variant has unique symbol names.
 */

#include "WolframLibrary.h"
#include "WolframIOLibraryFunctions.h"
#include <stdint.h>
#include <string.h>

/* ---------- Kyber ref headers (all three K variants are linked in) ---------- */

/* Kyber512 (K=2) */
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* Kyber768 (K=3) */
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* Kyber1024 (K=4) */
int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ---------- Size constants per security level ---------- */

/* K=2: Kyber512 */
#define KYBER512_PUBLIC_KEY_BYTES    800
#define KYBER512_SECRET_KEY_BYTES    1632
#define KYBER512_CIPHERTEXT_BYTES    768
#define KYBER_SHARED_SECRET_BYTES    32

/* K=3: Kyber768 */
#define KYBER768_PUBLIC_KEY_BYTES    1184
#define KYBER768_SECRET_KEY_BYTES    2400
#define KYBER768_CIPHERTEXT_BYTES    1088

/* K=4: Kyber1024 */
#define KYBER1024_PUBLIC_KEY_BYTES   1568
#define KYBER1024_SECRET_KEY_BYTES   3168
#define KYBER1024_CIPHERTEXT_BYTES   1568

/* ---------- Helpers ---------- */

static void bytes_to_tensor_data(const uint8_t *source, mint *destination, mint length) {
	for (mint i = 0; i < length; i++)
		destination[i] = (mint)source[i];
}

static void tensor_data_to_bytes(const mint *source, uint8_t *destination, mint length) {
	for (mint i = 0; i < length; i++)
		destination[i] = (uint8_t)(source[i] & 0xFF);
}

static int get_sizes(mint level, mint *publicKeySize, mint *secretKeySize, mint *ciphertextSize) {
	switch (level) {
		case 512:
			if (publicKeySize)  *publicKeySize  = KYBER512_PUBLIC_KEY_BYTES;
			if (secretKeySize)  *secretKeySize  = KYBER512_SECRET_KEY_BYTES;
			if (ciphertextSize) *ciphertextSize = KYBER512_CIPHERTEXT_BYTES;
			return 0;
		case 768:
			if (publicKeySize)  *publicKeySize  = KYBER768_PUBLIC_KEY_BYTES;
			if (secretKeySize)  *secretKeySize  = KYBER768_SECRET_KEY_BYTES;
			if (ciphertextSize) *ciphertextSize = KYBER768_CIPHERTEXT_BYTES;
			return 0;
		case 1024:
			if (publicKeySize)  *publicKeySize  = KYBER1024_PUBLIC_KEY_BYTES;
			if (secretKeySize)  *secretKeySize  = KYBER1024_SECRET_KEY_BYTES;
			if (ciphertextSize) *ciphertextSize = KYBER1024_CIPHERTEXT_BYTES;
			return 0;
		default:
			return 1;
	}
}

/* ---------- LibraryLink boilerplate ---------- */

DLLEXPORT mint WolframLibrary_getVersion(void) {
	return WolframLibraryVersion;
}

DLLEXPORT int WolframLibrary_initialize(WolframLibraryData libData) {
	(void)libData;
	return LIBRARY_NO_ERROR;
}

DLLEXPORT void WolframLibrary_uninitialize(WolframLibraryData libData) {
	(void)libData;
}

/* ---------- kyber_keygen ----------
* Args: {securityLevel (Integer)}
* Returns via DataStore: two Integer rank-1 tensors (pk, sk)
*/
DLLEXPORT int kyber_keygen(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Res) {
	(void)Argc;

	mint level = MArgument_getInteger(Args[0]);
	mint publicKeySize, secretKeySize;
	if (get_sizes(level, &publicKeySize, &secretKeySize, NULL))
		return LIBRARY_FUNCTION_ERROR;

	uint8_t publicKey[KYBER1024_PUBLIC_KEY_BYTES];   /* max sizes */
	uint8_t secretKey[KYBER1024_SECRET_KEY_BYTES];
	int returnCode;

	switch (level) {
		case 512:  returnCode = pqcrystals_kyber512_ref_keypair(publicKey, secretKey);  break;
		case 768:  returnCode = pqcrystals_kyber768_ref_keypair(publicKey, secretKey);  break;
		case 1024: returnCode = pqcrystals_kyber1024_ref_keypair(publicKey, secretKey); break;
		default:   return LIBRARY_FUNCTION_ERROR;
	}
	if (returnCode != 0) return LIBRARY_FUNCTION_ERROR;

	/* Create output tensors */
	MTensor publicKeyTensor, secretKeyTensor;
	int error;
	error = libData->MTensor_new(MType_Integer, 1, &publicKeySize, &publicKeyTensor);
	if (error) return error;
	error = libData->MTensor_new(MType_Integer, 1, &secretKeySize, &secretKeyTensor);
	if (error) { libData->MTensor_free(publicKeyTensor); return error; }

	bytes_to_tensor_data(publicKey, libData->MTensor_getIntegerData(publicKeyTensor), publicKeySize);
	bytes_to_tensor_data(secretKey, libData->MTensor_getIntegerData(secretKeyTensor), secretKeySize);

	/* Return via DataStore */
	DataStore dataStore = libData->ioLibraryFunctions->createDataStore();
	libData->ioLibraryFunctions->DataStore_addMTensor(dataStore, publicKeyTensor);
	libData->ioLibraryFunctions->DataStore_addMTensor(dataStore, secretKeyTensor);
	MArgument_setDataStore(Res, dataStore);

	return LIBRARY_NO_ERROR;
}

/* ---------- kyber_encapsulate ----------
* Args: {publicKey (Integer tensor rank-1), securityLevel (Integer)}
* Returns via DataStore: {ciphertext, sharedSecret} as Integer tensors
*/
DLLEXPORT int kyber_encapsulate(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Res) {
	(void)Argc;

	MTensor inputPublicKeyTensor = MArgument_getMTensor(Args[0]);
	mint level = MArgument_getInteger(Args[1]);

	mint publicKeySize, ciphertextSize;
	if (get_sizes(level, &publicKeySize, NULL, &ciphertextSize))
		return LIBRARY_FUNCTION_ERROR;

	if (libData->MTensor_getFlattenedLength(inputPublicKeyTensor) != publicKeySize)
		return LIBRARY_DIMENSION_ERROR;

	uint8_t publicKey[KYBER1024_PUBLIC_KEY_BYTES];
	tensor_data_to_bytes(libData->MTensor_getIntegerData(inputPublicKeyTensor), publicKey, publicKeySize);

	uint8_t ciphertext[KYBER1024_CIPHERTEXT_BYTES];
	uint8_t sharedSecret[KYBER_SHARED_SECRET_BYTES];
	int returnCode;

	switch (level) {
		case 512:  returnCode = pqcrystals_kyber512_ref_enc(ciphertext, sharedSecret, publicKey);  break;
		case 768:  returnCode = pqcrystals_kyber768_ref_enc(ciphertext, sharedSecret, publicKey);  break;
		case 1024: returnCode = pqcrystals_kyber1024_ref_enc(ciphertext, sharedSecret, publicKey); break;
		default:   return LIBRARY_FUNCTION_ERROR;
	}
	if (returnCode != 0) return LIBRARY_FUNCTION_ERROR;

	MTensor ciphertextTensor, sharedSecretTensor;
	mint sharedSecretSize = KYBER_SHARED_SECRET_BYTES;
	int error;
	error = libData->MTensor_new(MType_Integer, 1, &ciphertextSize, &ciphertextTensor);
	if (error) return error;
	error = libData->MTensor_new(MType_Integer, 1, &sharedSecretSize, &sharedSecretTensor);
	if (error) { libData->MTensor_free(ciphertextTensor); return error; }

	bytes_to_tensor_data(ciphertext, libData->MTensor_getIntegerData(ciphertextTensor), ciphertextSize);
	bytes_to_tensor_data(sharedSecret, libData->MTensor_getIntegerData(sharedSecretTensor), sharedSecretSize);

	DataStore dataStore = libData->ioLibraryFunctions->createDataStore();
	libData->ioLibraryFunctions->DataStore_addMTensor(dataStore, ciphertextTensor);
	libData->ioLibraryFunctions->DataStore_addMTensor(dataStore, sharedSecretTensor);
	MArgument_setDataStore(Res, dataStore);

	return LIBRARY_NO_ERROR;
}

/* ---------- kyber_decapsulate ----------
* Args: {ciphertext (Integer tensor), secretKey (Integer tensor), securityLevel (Integer)}
* Returns: sharedSecret (Integer tensor rank-1 of length 32)
*/
DLLEXPORT int kyber_decapsulate(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Res) {
	(void)Argc;

	MTensor inputCiphertextTensor = MArgument_getMTensor(Args[0]);
	MTensor inputSecretKeyTensor = MArgument_getMTensor(Args[1]);
	mint level = MArgument_getInteger(Args[2]);

	mint secretKeySize, ciphertextSize;
	if (get_sizes(level, NULL, &secretKeySize, &ciphertextSize))
		return LIBRARY_FUNCTION_ERROR;

	if (libData->MTensor_getFlattenedLength(inputCiphertextTensor) != ciphertextSize)
		return LIBRARY_DIMENSION_ERROR;
	if (libData->MTensor_getFlattenedLength(inputSecretKeyTensor) != secretKeySize)
		return LIBRARY_DIMENSION_ERROR;

	uint8_t ciphertext[KYBER1024_CIPHERTEXT_BYTES];
	uint8_t secretKey[KYBER1024_SECRET_KEY_BYTES];
	tensor_data_to_bytes(libData->MTensor_getIntegerData(inputCiphertextTensor), ciphertext, ciphertextSize);
	tensor_data_to_bytes(libData->MTensor_getIntegerData(inputSecretKeyTensor), secretKey, secretKeySize);

	uint8_t sharedSecret[KYBER_SHARED_SECRET_BYTES];
	int returnCode;

	switch (level) {
		case 512:  returnCode = pqcrystals_kyber512_ref_dec(sharedSecret, ciphertext, secretKey);  break;
		case 768:  returnCode = pqcrystals_kyber768_ref_dec(sharedSecret, ciphertext, secretKey);  break;
		case 1024: returnCode = pqcrystals_kyber1024_ref_dec(sharedSecret, ciphertext, secretKey); break;
		default:   return LIBRARY_FUNCTION_ERROR;
	}
	if (returnCode != 0) return LIBRARY_FUNCTION_ERROR;

	MTensor sharedSecretTensor;
	mint sharedSecretSize = KYBER_SHARED_SECRET_BYTES;
	int error = libData->MTensor_new(MType_Integer, 1, &sharedSecretSize, &sharedSecretTensor);
	if (error) return error;

	bytes_to_tensor_data(sharedSecret, libData->MTensor_getIntegerData(sharedSecretTensor), sharedSecretSize);
	MArgument_setMTensor(Res, sharedSecretTensor);

	return LIBRARY_NO_ERROR;
}
