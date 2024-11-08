/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/dylib.h>
#include "skf.h"
#include "skf_ext.h"
#include "skf_int.h"

#define SKFerr(e,r)

#define SKF_METHOD_BIND_FUNCTION_EX(func,name) \
	skf->func = (SKF_##func##_FuncPtr)dylib_get_function(skf->dso, "SKF_"#name)

#define SKF_METHOD_BIND_FUNCTION(func) \
	SKF_METHOD_BIND_FUNCTION_EX(func,func)


SKF_METHOD *SKF_METHOD_load_library(const char *so_path)
{
	SKF_METHOD *ret = NULL;
	SKF_METHOD *skf = NULL;

	if (!(skf = malloc(sizeof(*skf)))) {
		SKFerr(SKF_F_SKF_METHOD_LOAD_LIBRARY, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!(skf->dso = dylib_load_library(so_path))) {
		SKFerr(SKF_F_SKF_METHOD_LOAD_LIBRARY, SKF_R_DSO_LOAD_FAILURE);
		goto end;
	}

	SKF_METHOD_BIND_FUNCTION(WaitForDevEvent);
	SKF_METHOD_BIND_FUNCTION(CancelWaitForDevEvent);
	SKF_METHOD_BIND_FUNCTION(EnumDev);
	SKF_METHOD_BIND_FUNCTION(ConnectDev);
	SKF_METHOD_BIND_FUNCTION(DisConnectDev);
	SKF_METHOD_BIND_FUNCTION(GetDevState);
	SKF_METHOD_BIND_FUNCTION(SetLabel);
	SKF_METHOD_BIND_FUNCTION(GetDevInfo);
	SKF_METHOD_BIND_FUNCTION(LockDev);
	SKF_METHOD_BIND_FUNCTION(UnlockDev);
	SKF_METHOD_BIND_FUNCTION(Transmit);
	SKF_METHOD_BIND_FUNCTION(ChangeDevAuthKey);
	SKF_METHOD_BIND_FUNCTION(DevAuth);
	SKF_METHOD_BIND_FUNCTION(ChangePIN);
	SKF_METHOD_BIND_FUNCTION(GetPINInfo);
	SKF_METHOD_BIND_FUNCTION(VerifyPIN);
	SKF_METHOD_BIND_FUNCTION(UnblockPIN);
	SKF_METHOD_BIND_FUNCTION(ClearSecureState);
	SKF_METHOD_BIND_FUNCTION(CreateApplication);
	SKF_METHOD_BIND_FUNCTION(EnumApplication);
	SKF_METHOD_BIND_FUNCTION(DeleteApplication);
	SKF_METHOD_BIND_FUNCTION(OpenApplication);
	SKF_METHOD_BIND_FUNCTION(CloseApplication);
	SKF_METHOD_BIND_FUNCTION_EX(CreateObject,CreateFile);
	SKF_METHOD_BIND_FUNCTION_EX(DeleteObject,DeleteFile);
	SKF_METHOD_BIND_FUNCTION_EX(EnumObjects,EnumFiles);
	SKF_METHOD_BIND_FUNCTION_EX(GetObjectInfo,GetFileInfo);
	SKF_METHOD_BIND_FUNCTION_EX(ReadObject,ReadFile);
	SKF_METHOD_BIND_FUNCTION_EX(WriteObject,WriteFile);
	SKF_METHOD_BIND_FUNCTION(CreateContainer);
	SKF_METHOD_BIND_FUNCTION(DeleteContainer);
	SKF_METHOD_BIND_FUNCTION(EnumContainer);
	SKF_METHOD_BIND_FUNCTION(OpenContainer);
	SKF_METHOD_BIND_FUNCTION(CloseContainer);
	SKF_METHOD_BIND_FUNCTION(GetContainerType);
	SKF_METHOD_BIND_FUNCTION(ImportCertificate);
	SKF_METHOD_BIND_FUNCTION(ExportCertificate);
	SKF_METHOD_BIND_FUNCTION(ExportPublicKey);
	SKF_METHOD_BIND_FUNCTION(GenRandom);
	SKF_METHOD_BIND_FUNCTION(GenExtRSAKey);
	SKF_METHOD_BIND_FUNCTION(GenRSAKeyPair);
	SKF_METHOD_BIND_FUNCTION(ImportRSAKeyPair);
	SKF_METHOD_BIND_FUNCTION(RSASignData);
	SKF_METHOD_BIND_FUNCTION(RSAVerify);
	SKF_METHOD_BIND_FUNCTION(RSAExportSessionKey);
	SKF_METHOD_BIND_FUNCTION(ExtRSAPubKeyOperation);
	SKF_METHOD_BIND_FUNCTION(ExtRSAPriKeyOperation);
	SKF_METHOD_BIND_FUNCTION(GenECCKeyPair);
	SKF_METHOD_BIND_FUNCTION(ImportECCKeyPair);
	SKF_METHOD_BIND_FUNCTION(ECCSignData);
	SKF_METHOD_BIND_FUNCTION(ECCVerify);
	SKF_METHOD_BIND_FUNCTION(ECCExportSessionKey);
	SKF_METHOD_BIND_FUNCTION(ExtECCEncrypt);
	SKF_METHOD_BIND_FUNCTION(ExtECCDecrypt);
	SKF_METHOD_BIND_FUNCTION(ExtECCSign);
	SKF_METHOD_BIND_FUNCTION(ExtECCVerify);
	SKF_METHOD_BIND_FUNCTION(GenerateAgreementDataWithECC);
	SKF_METHOD_BIND_FUNCTION(GenerateAgreementDataAndKeyWithECC);
	SKF_METHOD_BIND_FUNCTION(GenerateKeyWithECC);
	SKF_METHOD_BIND_FUNCTION(ImportSessionKey);
	SKF_METHOD_BIND_FUNCTION(SetSymmKey);
	SKF_METHOD_BIND_FUNCTION(EncryptInit);
	SKF_METHOD_BIND_FUNCTION(Encrypt);
	SKF_METHOD_BIND_FUNCTION(EncryptUpdate);
	SKF_METHOD_BIND_FUNCTION(EncryptFinal);
	SKF_METHOD_BIND_FUNCTION(DecryptInit);
	SKF_METHOD_BIND_FUNCTION(Decrypt);
	SKF_METHOD_BIND_FUNCTION(DecryptUpdate);
	SKF_METHOD_BIND_FUNCTION(DecryptFinal);
	SKF_METHOD_BIND_FUNCTION(DigestInit);
	SKF_METHOD_BIND_FUNCTION(Digest);
	SKF_METHOD_BIND_FUNCTION(DigestUpdate);
	SKF_METHOD_BIND_FUNCTION(DigestFinal);
	SKF_METHOD_BIND_FUNCTION(MacInit);
	SKF_METHOD_BIND_FUNCTION(Mac);
	SKF_METHOD_BIND_FUNCTION(MacUpdate);
	SKF_METHOD_BIND_FUNCTION(MacFinal);
	SKF_METHOD_BIND_FUNCTION(CloseHandle);
#ifdef SKF_HAS_ECCDECRYPT
	SKF_METHOD_BIND_FUNCTION(ECCDecrypt);
#endif

	ret = skf;
	skf = NULL;

end:
	SKF_METHOD_free(skf);
	return ret;
}

void SKF_METHOD_free(SKF_METHOD *meth)
{
	if (meth)
		dylib_close_library(meth->dso);
	free(meth);
}
