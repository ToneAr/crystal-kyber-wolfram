BeginPackage["ToneAr`Kyber`FileScope`Main`", {
	"ToneAr`Kyber`",
	"ToneAr`Kyber`Private`"
}];
Begin["`Private`"];

(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* KyberKeyGen *)
(* Description:  Generate a Kyber key pair for a specified security level.
 * Return:       <|
 *                   "PublicKey"  -> _ByteArray,
 *                   "PrivateKey" -> _ByteArray,
 *                   "SecurityLevel" -> (512 | 768 | 1024)
 *               |>
 *)
KyberKeyGen[level_ : 768] := Module[{lvl, result, pvtKey, pubKey},

	kyberEnsureLoaded[];
	If[$kyberLibrary === $Failed, Return[$Failed]];

	lvl = normalizeSecurityLevel[level];
	If[lvl === $Failed,
		Message[KyberKeyGen::badlvl, level];
		Return[$Failed]
	];

	result = $kyberKeygen[lvl];
	pubKey = result[[1]];
	pvtKey = result[[2]];

	<|
		"PublicKey"  -> PublicKey[<|
			"Type" -> "ML-KEM",
			"Cipher" -> "ML-KEM",
			"ParameterSet" -> lvl,
			"PublicByteArray" -> ByteArray[pubKey]
		|>],
		"PrivateKey"  -> PrivateKey[<|
			"Type" -> "ML-KEM",
			"Cipher" -> "ML-KEM",
			"ParameterSet" -> lvl,
			"PublicByteArray" -> ByteArray[pubKey],
			"PrivateByteArray" -> ByteArray[pvtKey]
		|>]
	|>
];

(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* KyberEncapsulate *)
(* Description:  Encapsulate a shared secret using the recipient's public key and specified security level.
 * Return:       <|
 *                   "EncapsulatedKey" -> _EncapsulatedKey,
 *                   "SharedSecret"    -> _ByteArray
 *               |>
 *)
KyberEncapsulate[publicKey_List, level_ : 768] :=
	KyberEncapsulate[ByteArray[publicKey], level];
KyberEncapsulate[
	pubKey: PublicKey[
		KeyValuePattern[{
			"Type" -> "ML-KEM",
			"ParameterSet" -> (512 | 768 | 1024),
			"PublicByteArray" -> _ByteArray
		}]
	]
] := Module[{},
	KyberEncapsulate[pubKey["PublicByteArray"], pubKey["ParameterSet"]]
];
KyberEncapsulate[publicKey_ByteArray, level_ : 768] := Module[
	{lvl, pkData, result, ct, ss, cipher},

	kyberEnsureLoaded[];
	If[$kyberLibrary === $Failed, Return[$Failed]];

	lvl = normalizeSecurityLevel[level];
	If[lvl === $Failed,
		Message[KyberEncapsulate::badlvl, level];
		Return[$Failed]
	];

	pkData = Normal[publicKey];

	result = $kyberEncapsulate[pkData, lvl];
	ct = result[[1]];
	ss = result[[2]];

	cipher = Switch[lvl,
		512,  "AES128",
		768,  "AES256",
		1024, "AES256",
		_,   $Failed
	];

	<|
		"EncapsulatedKey" ->
			EncapsulatedKey[<|
				"Type"         -> "ML-KEM",
				"ParameterSet" -> lvl,
				"CipherText"   -> ByteArray[ct]
			|>],
		"SharedSecret" ->
			SymmetricKey[<|
				"Cipher"  -> cipher,
				"Key"     -> ByteArray[ss]
			|>]
	|>
];


(* -------------------------------------------------------------------------- *)
(* ::Section:: *)(* KyberDecapsulate *)
(* Description:  Decapsulate a ciphertext using the recipient's private key and specified security level to recover the shared secret.
 * Return:       _ByteArray
 *)
KyberDecapsulate[
	cipherText_EncapsulatedKey,
	privateKey_
] := Module[{},
	KyberDecapsulate[cipherText["CipherText"], privateKey]
];
KyberDecapsulate[
	cipherText_,
	privateKey: PrivateKey[
		KeyValuePattern[{
			"Type" -> "ML-KEM",
			"ParameterSet" -> (512 | 768 | 1024),
			"PublicByteArray" -> _ByteArray,
			"PrivateByteArray" -> _ByteArray
		}]
	]
] := Module[{},
	KyberDecapsulate[cipherText, privateKey["PrivateByteArray"]]
];
KyberDecapsulate[ciphertext_List, secretKey_List, level_ : 768] :=
	KyberDecapsulate[ByteArray[ciphertext], ByteArray[secretKey], level];
KyberDecapsulate[ciphertext_ByteArray, secretKey_ByteArray, level_ : 768] := Module[
	{lvl, ctData, skData, ssData, cipher},

	kyberEnsureLoaded[];
	If[$kyberLibrary === $Failed, Return[$Failed]];

	lvl = normalizeSecurityLevel[level];
	If[lvl === $Failed,
		Message[KyberDecapsulate::badlvl, level];
		Return[$Failed]
	];

	ctData = Normal[ciphertext];
	skData = Normal[secretKey];

	ssData = $kyberDecapsulate[ctData, skData, lvl];

	cipher = Switch[lvl,
		512,  "AES128",
		768,  "AES256",
		1024, "AES256",
		_,   $Failed
	];

	SymmetricKey[<|
		"Cipher"  -> cipher,
		"Key"     -> ByteArray[ssData]
	|>]
];

End[];
EndPackage[];
