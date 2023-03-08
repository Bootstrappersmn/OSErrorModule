//
//  OSStatus+extensions.swift
//  
//
//  Created by Jeremy Bannister on 3/8/23.
//

///
public extension OSStatus {
    
    ///
    var asOSError: OSError? {
        switch self {
        case errSecSuccess:
            return nil
        
        case errSecUnimplemented:
            return .errSecUnimplemented
        
        case errSecDiskFull:
            return .errSecDiskFull
        
        case errSecIO:
            return .errSecIO
        
        case errSecOpWr:
            return .errSecOpWr
        
        case errSecParam:
            return .errSecParam
        
        case errSecWrPerm:
            return .errSecWrPerm
        
        case errSecAllocate:
            return .errSecAllocate
        
        case errSecUserCanceled:
            return .errSecUserCanceled
        
        case errSecBadReq:
            return .errSecBadReq

        // MARK: - Internal Error Result Codes
        
        case errSecInternalComponent:
            return .errSecInternalComponent
        
        case errSecCoreFoundationUnknown:
            return .errSecCoreFoundationUnknown
        
        case errSecInternalError:
            return .errSecInternalError

        // MARK: - Keychain Result Codes
        
        case errSecNotAvailable:
            return .errSecNotAvailable
        
        case errSecReadOnly:
            return .errSecReadOnly
        
        case errSecAuthFailed:
            return .errSecAuthFailed
        
        case errSecNoSuchKeychain:
            return .errSecNoSuchKeychain
        
        case errSecInvalidKeychain:
            return .errSecInvalidKeychain
        
        case errSecDuplicateKeychain:
            return .errSecDuplicateKeychain
        
        case errSecDuplicateCallback:
            return .errSecDuplicateCallback
        
        case errSecInvalidCallback:
            return .errSecInvalidCallback
        
        case errSecDuplicateItem:
            return .errSecDuplicateItem
        
        case errSecItemNotFound:
            return .errSecItemNotFound
        
        case errSecBufferTooSmall:
            return .errSecBufferTooSmall
        
        case errSecDataTooLarge:
            return .errSecDataTooLarge
        
        case errSecNoSuchAttr:
            return .errSecNoSuchAttr
        
        case errSecInvalidItemRef:
            return .errSecInvalidItemRef
        
        case errSecInvalidSearchRef:
            return .errSecInvalidSearchRef
        
        case errSecNoSuchClass:
            return .errSecNoSuchClass
        
        case errSecNoDefaultKeychain:
            return .errSecNoDefaultKeychain
        
        case errSecInteractionNotAllowed:
            return .errSecInteractionNotAllowed
        
        case errSecReadOnlyAttr:
            return .errSecReadOnlyAttr
        
        case errSecWrongSecVersion:
            return .errSecWrongSecVersion
        
        case errSecKeySizeNotAllowed:
            return .errSecKeySizeNotAllowed
        
        case errSecNoStorageModule:
            return .errSecNoStorageModule
        
        case errSecNoCertificateModule:
            return .errSecNoCertificateModule
        
        case errSecNoPolicyModule:
            return .errSecNoPolicyModule
        
        case errSecInteractionRequired:
            return .errSecInteractionRequired
        
        case errSecDataNotAvailable:
            return .errSecDataNotAvailable
        
        case errSecDataNotModifiable:
            return .errSecDataNotModifiable
        
        case errSecCreateChainFailed:
            return .errSecCreateChainFailed
        
        case errSecInvalidPrefsDomain:
            return .errSecInvalidPrefsDomain
        
        case errSecInDarkWake:
            return .errSecInDarkWake

        // MARK: - Certificate Result Codes
        
        case errSecUnknownCriticalExtensionFlag:
            return .errSecUnknownCriticalExtensionFlag
        
        case errSecCertificateCannotOperate:
            return .errSecCertificateCannotOperate
        
        case errSecCertificateExpired:
            return .errSecCertificateExpired
        
        case errSecCertificateNotValidYet:
            return .errSecCertificateNotValidYet
        
        case errSecCertificateRevoked:
            return .errSecCertificateRevoked
        
        case errSecCertificateSuspended:
            return .errSecCertificateSuspended
        
        case errSecInvalidCertAuthority:
            return .errSecInvalidCertAuthority
        
        case errSecInvalidCertificateGroup:
            return .errSecInvalidCertificateGroup
        
        case errSecInvalidCertificateRef:
            return .errSecInvalidCertificateRef
        
        case errSecCertificateNameNotAllowed:
            return .errSecCertificateNameNotAllowed
        
        case errSecCertificatePolicyNotAllowed:
            return .errSecCertificatePolicyNotAllowed
        
        case errSecCertificateValidityPeriodTooLong:
            return .errSecCertificateValidityPeriodTooLong

        // MARK: - ACL Result Codes
        
        case errSecACLAddFailed:
            return .errSecACLAddFailed
        
        case errSecACLChangeFailed:
            return .errSecACLChangeFailed
        
        case errSecACLDeleteFailed:
            return .errSecACLDeleteFailed
        
        case errSecACLNotSimple:
            return .errSecACLNotSimple
        
        case errSecACLReplaceFailed:
            return .errSecACLReplaceFailed
        
        case errSecAppleAddAppACLSubject:
            return .errSecAppleAddAppACLSubject
        
        case errSecInvalidBaseACLs:
            return .errSecInvalidBaseACLs
        
        case errSecInvalidACL:
            return .errSecInvalidACL

        // MARK: - CRL Result Codes
        
        case errSecCRLExpired:
            return .errSecCRLExpired
        
        case errSecCRLNotValidYet:
            return .errSecCRLNotValidYet
        
        case errSecCRLNotFound:
            return .errSecCRLNotFound
        
        case errSecCRLServerDown:
            return .errSecCRLServerDown
        
        case errSecCRLBadURI:
            return .errSecCRLBadURI
        
        case errSecCRLNotTrusted:
            return .errSecCRLNotTrusted
        
        case errSecUnknownCertExtension:
            return .errSecUnknownCertExtension
        
        case errSecUnknownCRLExtension:
            return .errSecUnknownCRLExtension
        
        case errSecCRLPolicyFailed:
            return .errSecCRLPolicyFailed
        
        case errSecCRLAlreadySigned:
            return .errSecCRLAlreadySigned
        
        case errSecIDPFailure:
            return .errSecIDPFailure
        
        case errSecInvalidCRLEncoding:
            return .errSecInvalidCRLEncoding
        
        case errSecInvalidCRLType:
            return .errSecInvalidCRLType
        
        case errSecInvalidCRL:
            return .errSecInvalidCRL
        
        case errSecInvalidCRLGroup:
            return .errSecInvalidCRLGroup
        
        case errSecInvalidCRLIndex:
            return .errSecInvalidCRLIndex
        
        case errSecInvalidCRLAuthority:
            return .errSecInvaldCRLAuthority

        // MARK: - SMIME Result Codes
        
        case errSecSMIMEEmailAddressesNotFound:
            return .errSecSMIMEEmailAddressesNotFound
        
        case errSecSMIMEBadExtendedKeyUsage:
            return .errSecSMIMEBadExtendedKeyUsage
        
        case errSecSMIMEBadKeyUsage:
            return .errSecSMIMEBadKeyUsage
        
        case errSecSMIMEKeyUsageNotCritical:
            return .errSecSMIMEKeyUsageNotCritical
        
        case errSecSMIMENoEmailAddress:
            return .errSecSMIMENoEmailAddress
        
        case errSecSMIMESubjAltNameNotCritical:
            return .errSecSMIMESubjAltNameNotCritical
        
        case errSecSSLBadExtendedKeyUsage:
            return .errSecSSLBadExtendedKeyUsage

        // MARK: - OCSP Result Codes
        
        case errSecOCSPBadResponse:
            return .errSecOCSPBadResponse
        
        case errSecOCSPBadRequest:
            return .errSecOCSPBadRequest
        
        case errSecOCSPUnavailable:
            return .errSecOCSPUnavailable
        
        case errSecOCSPStatusUnrecognized:
            return .errSecOCSPStatusUnrecognized
        
        case errSecEndOfData:
            return .errSecEndOfData
        
        case errSecIncompleteCertRevocationCheck:
            return .errSecIncompleteCertRevocationCheck
        
        case errSecNetworkFailure:
            return .errSecNetworkFailure
        
        case errSecOCSPNotTrustedToAnchor:
            return .errSecOCSPNotTrustedToAnchor
        
        case errSecRecordModified:
            return .errSecRecordModified
        
        case errSecOCSPSignatureError:
            return .errSecOCSPSignatureError
        
        case errSecOCSPNoSigner:
            return .errSecOCSPNoSigner
        
        case errSecOCSPResponderMalformedReq:
            return .errSecOCSPResponderMalformedReq
        
        case errSecOCSPResponderInternalError:
            return .errSecOCSPResponderInternalError
        
        case errSecOCSPResponderTryLater:
            return .errSecOCSPResponderTryLater
        
        case errSecOCSPResponderSignatureRequired:
            return .errSecOCSPResponderSignatureRequired
        
        case errSecOCSPResponderUnauthorized:
            return .errSecOCSPResponderUnauthorized
        
        case errSecOCSPResponseNonceMismatch:
            return .errSecOCSPResponseNonceMismatch

        // MARK: - Code Signing Result Codes
        
        case errSecCodeSigningBadCertChainLength:
            return .errSecCodeSigningBadCertChainLength
        
        case errSecCodeSigningNoBasicConstraints:
            return .errSecCodeSigningNoBasicConstraints
        
        case errSecCodeSigningBadPathLengthConstraint:
            return .errSecCodeSigningBadPathLengthConstraint
        
        case errSecCodeSigningNoExtendedKeyUsage:
            return .errSecCodeSigningNoExtendedKeyUsage
        
        case errSecCodeSigningDevelopment:
            return .errSecCodeSigningDevelopment
        
        case errSecResourceSignBadCertChainLength:
            return .errSecResourceSignBadCertChainLength
        
        case errSecResourceSignBadExtKeyUsage:
            return .errSecResourceSignBadExtKeyUsage
        
        case errSecTrustSettingDeny:
            return .errSecTrustSettingDeny
        
        case errSecInvalidSubjectName:
            return .errSecInvalidSubjectName
        
        case errSecUnknownQualifiedCertStatement:
            return .errSecUnknownQualifiedCertStatement

        // MARK: - Mobile Me Result Codes
        
        case errSecMobileMeRequestQueued:
            return .errSecMobileMeRequestQueued
        
        case errSecMobileMeRequestRedirected:
            return .errSecMobileMeRequestRedirected
        
        case errSecMobileMeServerError:
            return .errSecMobileMeServerError
        
        case errSecMobileMeServerNotAvailable:
            return .errSecMobileMeServerNotAvailable
        
        case errSecMobileMeServerAlreadyExists:
            return .errSecMobileMeServerAlreadyExists
        
        case errSecMobileMeServerServiceErr:
            return .errSecMobileMeServerServiceErr
        
        case errSecMobileMeRequestAlreadyPending:
            return .errSecMobileMeRequestAlreadyPending
        
        case errSecMobileMeNoRequestPending:
            return .errSecMobileMeNoRequestPending
        
        case errSecMobileMeCSRVerifyFailure:
            return .errSecMobileMeCSRVerifyFailure
        
        case errSecMobileMeFailedConsistencyCheck:
            return .errSecMobileMeFailedConsistencyCheck

        // MARK: - Cryptographic Key Result Codes
        
        case errSecKeyUsageIncorrect:
            return .errSecKeyUsageIncorrect
        
        case errSecKeyBlobTypeIncorrect:
            return .errSecKeyBlobTypeIncorrect
        
        case errSecKeyHeaderInconsistent:
            return .errSecKeyHeaderInconsistent
        
        case errSecKeyIsSensitive:
            return .errSecKeyIsSensitive
        
        case errSecUnsupportedKeyFormat:
            return .errSecUnsupportedKeyFormat
        
        case errSecUnsupportedKeySize:
            return .errSecUnsupportedKeySize
        
        case errSecInvalidKeyUsageMask:
            return .errSecInvalidKeyUsageMask
        
        case errSecUnsupportedKeyUsageMask:
            return .errSecUnsupportedKeyUsageMask
        
        case errSecInvalidKeyAttributeMask:
            return .errSecInvalidKeyAttributeMask
        
        case errSecUnsupportedKeyAttributeMask:
            return .errSecUnsupportedKeyAttributeMask
        
        case errSecInvalidKeyLabel:
            return .errSecInvalidKeyLabel
        
        case errSecUnsupportedKeyLabel:
            return .errSecUnsupportedKeyLabel
        
        case errSecInvalidKeyFormat:
            return .errSecInvalidKeyFormat
        
        case errSecInvalidKeyBlob:
            return .errSecInvalidKeyBlob
        
        case errSecInvalidKeyHierarchy:
            return .errSecInvalidKeyHierarchy
        
        case errSecInvalidKeyRef:
            return .errSecInvalidKeyRef
        
        case errSecInvalidKeyUsageForPolicy:
            return .errSecInvalidKeyUsageForPolicy

        // MARK: - Invalid Attribute Result Codes
        
        case errSecInvalidAttributeKey:
            return .errSecInvalidAttributeKey
        
        case errSecInvalidAttributeInitVector:
            return .errSecInvalidAttributeInitVector
        
        case errSecInvalidAttributeSalt:
            return .errSecInvalidAttributeSalt
        
        case errSecInvalidAttributePadding:
            return .errSecInvalidAttributePadding
        
        case errSecInvalidAttributeRandom:
            return .errSecInvalidAttributeRandom
        
        case errSecInvalidAttributeSeed:
            return .errSecInvalidAttributeSeed
        
        case errSecInvalidAttributePassphrase:
            return .errSecInvalidAttributePassphrase
        
        case errSecInvalidAttributeKeyLength:
            return .errSecInvalidAttributeKeyLength
        
        case errSecInvalidAttributeBlockSize:
            return .errSecInvalidAttributeBlockSize
        
        case errSecInvalidAttributeOutputSize:
            return .errSecInvalidAttributeOutputSize
        
        case errSecInvalidAttributeRounds:
            return .errSecInvalidAttributeRounds
        
        case errSecInvalidAlgorithmParms:
            return .errSecInvalidAlgorithmParms
        
        case errSecInvalidAttributeLabel:
            return .errSecInvalidAttributeLabel
        
        case errSecInvalidAttributeKeyType:
            return .errSecInvalidAttributeKeyType
        
        case errSecInvalidAttributeMode:
            return .errSecInvalidAttributeMode
        
        case errSecInvalidAttributeEffectiveBits:
            return .errSecInvalidAttributeEffectiveBits
        
        case errSecInvalidAttributeStartDate:
            return .errSecInvalidAttributeStartDate
        
        case errSecInvalidAttributeEndDate:
            return .errSecInvalidAttributeEndDate
        
        case errSecInvalidAttributeVersion:
            return .errSecInvalidAttributeVersion
        
        case errSecInvalidAttributePrime:
            return .errSecInvalidAttributePrime
        
        case errSecInvalidAttributeBase:
            return .errSecInvalidAttributeBase
        
        case errSecInvalidAttributeSubprime:
            return .errSecInvalidAttributeSubprime
        
        case errSecInvalidAttributeIterationCount:
            return .errSecInvalidAttributeIterationCount
        
        case errSecInvalidAttributeDLDBHandle:
            return .errSecInvalidAttributeDLDBHandle
        
        case errSecInvalidAttributeAccessCredentials:
            return .errSecInvalidAttributeAccessCredentials
        
        case errSecInvalidAttributePublicKeyFormat:
            return .errSecInvalidAttributePublicKeyFormat
        
        case errSecInvalidAttributePrivateKeyFormat:
            return .errSecInvalidAttributePrivateKeyFormat
        
        case errSecInvalidAttributeSymmetricKeyFormat:
            return .errSecInvalidAttributeSymmetricKeyFormat
        
        case errSecInvalidAttributeWrappedKeyFormat:
            return .errSecInvalidAttributeWrappedKeyFormat

        // MARK: - Missing Attribute Result Codes
        
        case errSecMissingAttributeKey:
            return .errSecMissingAttributeKey
        
        case errSecMissingAttributeInitVector:
            return .errSecMissingAttributeInitVector
        
        case errSecMissingAttributeSalt:
            return .errSecMissingAttributeSalt
        
        case errSecMissingAttributePadding:
            return .errSecMissingAttributePadding
        
        case errSecMissingAttributeRandom:
            return .errSecMissingAttributeRandom
        
        case errSecMissingAttributeSeed:
            return .errSecMissingAttributeSeed
        
        case errSecMissingAttributePassphrase:
            return .errSecMissingAttributePassphrase
        
        case errSecMissingAttributeKeyLength:
            return .errSecMissingAttributeKeyLength
        
        case errSecMissingAttributeBlockSize:
            return .errSecMissingAttributeBlockSize
        
        case errSecMissingAttributeOutputSize:
            return .errSecMissingAttributeOutputSize
        
        case errSecMissingAttributeRounds:
            return .errSecMissingAttributeRounds
        
        case errSecMissingAlgorithmParms:
            return .errSecMissingAlgorithmParms
        
        case errSecMissingAttributeLabel:
            return .errSecMissingAttributeLabel
        
        case errSecMissingAttributeKeyType:
            return .errSecMissingAttributeKeyType
        
        case errSecMissingAttributeMode:
            return .errSecMissingAttributeMode
        
        case errSecMissingAttributeEffectiveBits:
            return .errSecMissingAttributeEffectiveBits
        
        case errSecMissingAttributeStartDate:
            return .errSecMissingAttributeStartDate
        
        case errSecMissingAttributeEndDate:
            return .errSecMissingAttributeEndDate
        
        case errSecMissingAttributeVersion:
            return .errSecMissingAttributeVersion
        
        case errSecMissingAttributePrime:
            return .errSecMissingAttributePrime
        
        case errSecMissingAttributeBase:
            return .errSecMissingAttributeBase
        
        case errSecMissingAttributeSubprime:
            return .errSecMissingAttributeSubprime
        
        case errSecMissingAttributeIterationCount:
            return .errSecMissingAttributeIterationCount
        
        case errSecMissingAttributeDLDBHandle:
            return .errSecMissingAttributeDLDBHandle
        
        case errSecMissingAttributeAccessCredentials:
            return .errSecMissingAttributeAccessCredentials
        
        case errSecMissingAttributePublicKeyFormat:
            return .errSecMissingAttributePublicKeyFormat
        
        case errSecMissingAttributePrivateKeyFormat:
            return .errSecMissingAttributePrivateKeyFormat
        
        case errSecMissingAttributeSymmetricKeyFormat:
            return .errSecMissingAttributeSymmetricKeyFormat
        
        case errSecMissingAttributeWrappedKeyFormat:
            return .errSecMissingAttributeWrappedKeyFormat

        // MARK: - Timestamp Result Codes
        
        case errSecTimestampMissing:
            return .errSecTimestampMissing
        
        case errSecTimestampInvalid:
            return .errSecTimestampInvalid
        
        case errSecTimestampNotTrusted:
            return .errSecTimestampNotTrusted
        
        case errSecTimestampServiceNotAvailable:
            return .errSecTimestampServiceNotAvailable
        
        case errSecTimestampBadAlg:
            return .errSecTimestampBadAlg
        
        case errSecTimestampBadRequest:
            return .errSecTimestampBadRequest
        
        case errSecTimestampBadDataFormat:
            return .errSecTimestampBadDataFormat
        
        case errSecTimestampTimeNotAvailable:
            return .errSecTimestampTimeNotAvailable
        
        case errSecTimestampUnacceptedPolicy:
            return .errSecTimestampUnacceptedPolicy
        
        case errSecTimestampUnacceptedExtension:
            return .errSecTimestampUnacceptedExtension
        
        case errSecTimestampAddInfoNotAvailable:
            return .errSecTimestampAddInfoNotAvailable
        
        case errSecTimestampSystemFailure:
            return .errSecTimestampSystemFailure
        
        case errSecSigningTimeMissing:
            return .errSecSigningTimeMissing
        
        case errSecTimestampRejection:
            return .errSecTimestampRejection
        
        case errSecTimestampWaiting:
            return .errSecTimestampWaiting
        
        case errSecTimestampRevocationWarning:
            return .errSecTimestampRevocationWarning
        
        case errSecTimestampRevocationNotification:
            return .errSecTimestampRevocationNotification

        // MARK: - Other Result Codes
        
        case errSecAddinLoadFailed:
            return .errSecAddinLoadFailed
        
        case errSecAddinUnloadFailed:
            return .errSecAddinUnloadFailed
        
        case errSecAlgorithmMismatch:
            return .errSecAlgorithmMismatch
        
        case errSecAlreadyLoggedIn:
            return .errSecAlreadyLoggedIn
        
        case errSecAppleInvalidKeyEndDate:
            return .errSecAppleInvalidKeyEndDate
        
        case errSecAppleInvalidKeyStartDate:
            return .errSecAppleInvalidKeyStartDate
        
        case errSecApplePublicKeyIncomplete:
            return .errSecApplePublicKeyIncomplete
        
        case errSecAppleSSLv2Rollback:
            return .errSecAppleSSLv2Rollback
        
        case errSecAppleSignatureMismatch:
            return .errSecAppleSignatureMismatch
        
        case errSecAttachHandleBusy:
            return .errSecAttachHandleBusy
        
        case errSecAttributeNotInContext:
            return .errSecAttributeNotInContext
        
        case errSecBlockSizeMismatch:
            return .errSecBlockSizeMismatch
        
        case errSecCallbackFailed:
            return .errSecCallbackFailed
        
        case errSecConversionError:
            return .errSecConversionError
        
        case errSecDatabaseLocked:
            return .errSecDatabaseLocked
        
        case errSecDatastoreIsOpen:
            return .errSecDatastoreIsOpen
        
        case errSecDecode:
            return .errSecDecode
        
        case errSecDeviceError:
            return .errSecDeviceError
        
        case errSecDeviceFailed:
            return .errSecDeviceFailed
        
        case errSecDeviceReset:
            return .errSecDeviceReset
        
        case errSecDeviceVerifyFailed:
            return .errSecDeviceVerifyFailed
        
        case errSecEMMLoadFailed:
            return .errSecEMMLoadFailed
        
        case errSecEMMUnloadFailed:
            return .errSecEMMUnloadFailed
        
        case errSecEventNotificationCallbackNotFound:
            return .errSecEventNotificationCallbackNotFound
        
        case errSecExtendedKeyUsageNotCritical:
            return .errSecExtendedKeyUsageNotCritical
        
        case errSecFieldSpecifiedMultiple:
            return .errSecFieldSpecifiedMultiple
        
        case errSecFileTooBig:
            return .errSecFileTooBig
        
        case errSecFunctionFailed:
            return .errSecFunctionFailed
        
        case errSecFunctionIntegrityFail:
            return .errSecFunctionIntegrityFail
        
        case errSecHostNameMismatch:
            return .errSecHostNameMismatch
        
        case errSecIncompatibleDatabaseBlob:
            return .errSecIncompatibleDatabaseBlob
        
        case errSecIncompatibleFieldFormat:
            return .errSecIncompatibleFieldFormat
        
        case errSecIncompatibleKeyBlob:
            return .errSecIncompatibleKeyBlob
        
        case errSecIncompatibleVersion:
            return .errSecIncompatibleVersion
        
        case errSecInputLengthError:
            return .errSecInputLengthError
        
        case errSecInsufficientClientID:
            return .errSecInsufficientClientID
        
        case errSecInsufficientCredentials:
            return .errSecInsufficientCredentials
        
        case errSecInvalidAccessCredentials:
            return .errSecInvalidAccessCredentials
        
        case errSecInvalidAccessRequest:
            return .errSecInvalidAccessRequest
        
        case errSecInvalidAction:
            return .errSecInvalidAction
        
        case errSecInvalidAddinFunctionTable:
            return .errSecInvalidAddinFunctionTable
        
        case errSecInvalidAlgorithm:
            return .errSecInvalidAlgorithm
        
        case errSecInvalidAuthority:
            return .errSecInvalidAuthority
        
        case errSecInvalidAuthorityKeyID:
            return .errSecInvalidAuthorityKeyID
        
        case errSecInvalidBundleInfo:
            return .errSecInvalidBundleInfo
        
        case errSecInvalidContext:
            return .errSecInvalidContext
        
        case errSecInvalidDBList:
            return .errSecInvalidDBList
        
        case errSecInvalidDBLocation:
            return .errSecInvalidDBLocation
        
        case errSecInvalidData:
            return .errSecInvalidData
        
        case errSecInvalidDatabaseBlob:
            return .errSecInvalidDatabaseBlob
        
        case errSecInvalidDigestAlgorithm:
            return .errSecInvalidDigestAlgorithm
        
        case errSecInvalidEncoding:
            return .errSecInvalidEncoding
        
        case errSecInvalidExtendedKeyUsage:
            return .errSecInvalidExtendedKeyUsage
        
        case errSecInvalidFormType:
            return .errSecInvalidFormType
        
        case errSecInvalidGUID:
            return .errSecInvalidGUID
        
        case errSecInvalidHandle:
            return .errSecInvalidHandle
        
        case errSecInvalidHandleUsage:
            return .errSecInvalidHandleUsage
        
        case errSecInvalidID:
            return .errSecInvalidID
        
        case errSecInvalidIDLinkage:
            return .errSecInvalidIDLinkage
        
        case errSecInvalidIdentifier:
            return .errSecInvalidIdentifier
        
        case errSecInvalidIndex:
            return .errSecInvalidIndex
        
        case errSecInvalidIndexInfo:
            return .errSecInvalidIndexInfo
        
        case errSecInvalidInputVector:
            return .errSecInvalidInputVector
        
        case errSecInvalidLoginName:
            return .errSecInvalidLoginName
        
        case errSecInvalidModifyMode:
            return .errSecInvalidModifyMode
        
        case errSecInvalidName:
            return .errSecInvalidName
        
        case errSecInvalidNetworkAddress:
            return .errSecInvalidNetworkAddress
        
        case errSecInvalidNewOwner:
            return .errSecInvalidNewOwner
        
        case errSecInvalidNumberOfFields:
            return .errSecInvalidNumberOfFields
        
        case errSecInvalidOutputVector:
            return .errSecInvalidOutputVector
        
        case errSecInvalidOwnerEdit:
            return .errSecInvalidOwnerEdit
        
        case errSecInvalidPVC:
            return .errSecInvalidPVC
        
        case errSecInvalidParsingModule:
            return .errSecInvalidParsingModule
        
        case errSecInvalidPassthroughID:
            return .errSecInvalidPassthroughID
        
        case errSecInvalidPasswordRef:
            return .errSecInvalidPasswordRef
        
        case errSecInvalidPointer:
            return .errSecInvalidPointer
        
        case errSecInvalidPolicyIdentifiers:
            return .errSecInvalidPolicyIdentifiers
        
        case errSecInvalidQuery:
            return .errSecInvalidQuery
        
        case errSecInvalidReason:
            return .errSecInvalidReason
        
        case errSecInvalidRecord:
            return .errSecInvalidRecord
        
        case errSecInvalidRequestInputs:
            return .errSecInvalidRequestInputs
        
        case errSecInvalidRequestor:
            return .errSecInvalidRequestor
        
        case errSecInvalidResponseVector:
            return .errSecInvalidResponseVector
        
        case errSecInvalidRoot:
            return .errSecInvalidRoot
        
        case errSecInvalidSampleValue:
            return .errSecInvalidSampleValue
        
        case errSecInvalidScope:
            return .errSecInvalidScope
        
        case errSecInvalidServiceMask:
            return .errSecInvalidServiceMask
        
        case errSecInvalidSignature:
            return .errSecInvalidSignature
        
        case errSecInvalidStopOnPolicy:
            return .errSecInvalidStopOnPolicy
        
        case errSecInvalidSubServiceID:
            return .errSecInvalidSubServiceID
        
        case errSecInvalidSubjectKeyID:
            return .errSecInvalidSubjectKeyID
        
        case errSecInvalidTimeString:
            return .errSecInvalidTimeString
        
        case errSecInvalidTrustSetting:
            return .errSecInvalidTrustSetting
        
        case errSecInvalidTrustSettings:
            return .errSecInvalidTrustSettings
        
        case errSecInvalidTuple:
            return .errSecInvalidTuple
        
        case errSecInvalidTupleCredentials:
            return .errSecInvalidTupleCredendtials
        
        case errSecInvalidTupleGroup:
            return .errSecInvalidTupleGroup
        
        case errSecInvalidValidityPeriod:
            return .errSecInvalidValidityPeriod
        
        case errSecInvalidValue:
            return .errSecInvalidValue
        
        case errSecLibraryReferenceNotFound:
            return .errSecLibraryReferenceNotFound
        
        case errSecMDSError:
            return .errSecMDSError
        
        case errSecMemoryError:
            return .errSecMemoryError
        
        case errSecMissingEntitlement:
            return .errSecMissingEntitlement
        
        case errSecMissingRequiredExtension:
            return .errSecMissingRequiredExtension
        
        case errSecMissingValue:
            return .errSecMissingValue
        
        case errSecModuleManagerInitializeFailed:
            return .errSecModuleManagerInitializeFailed
        
        case errSecModuleManagerNotFound:
            return .errSecModuleManagerNotFound
        
        case errSecModuleManifestVerifyFailed:
            return .errSecModuleManifestVerifyFailed
        
        case errSecModuleNotLoaded:
            return .errSecModuleNotLoaded
        
        case errSecMultiplePrivKeys:
            return .errSecMultiplePrivKeys
        
        case errSecMultipleValuesUnsupported:
            return .errSecMultipleValuesUnsupported
        
        case errSecNoAccessForItem:
            return .errSecNoAccessForItem
        
        case errSecNoBasicConstraints:
            return .errSecNoBasicConstraints
        
        case errSecNoBasicConstraintsCA:
            return .errSecNoBasicConstraintsCA
        
        case errSecNoDefaultAuthority:
            return .errSecNoDefaultAuthority
        
        case errSecNoFieldValues:
            return .errSecNoFieldValues
        
        case errSecNoTrustSettings:
            return .errSecNoTrustSettings
        
        case errSecNotInitialized:
            return .errSecNotInitialized
        
        case errSecNotLoggedIn:
            return .errSecNotLoggedIn
        
        case errSecNotSigner:
            return .errSecNotSigner
        
        case errSecNotTrusted:
            return .errSecNotTrusted
        
        case errSecOutputLengthError:
            return .errSecOutputLengthError
        
        case errSecPVCAlreadyConfigured:
            return .errSecPVCAlreadyConfigured
        
        case errSecPVCReferentNotFound:
            return .errSecPVCReferentNotFound
        
        case errSecPassphraseRequired:
            return .errSecPassphraseRequired
        
        case errSecPathLengthConstraintExceeded:
            return .errSecPathLengthConstraintExceeded
        
        case errSecPkcs12VerifyFailure:
            return .errSecPkcs12VerifyFailure
        
        case errSecPolicyNotFound:
            return .errSecPolicyNotFound
        
        case errSecPrivilegeNotGranted:
            return .errSecPrivilegeNotGranted
        
        case errSecPrivilegeNotSupported:
            return .errSecPrivilegeNotSupported
        
        case errSecPublicKeyInconsistent:
            return .errSecPublicKeyInconsistent
        
        case errSecQuerySizeUnknown:
            return .errSecQuerySizeUnknown
        
        case errSecQuotaExceeded:
            return .errSecQuotaExceeded
        
        case errSecRejectedForm:
            return .errSecRejectedForm
        
        case errSecRequestDescriptor:
            return .errSecRequestDescriptor
        
        case errSecRequestLost:
            return .errSecRequestLost
        
        case errSecRequestRejected:
            return .errSecRequestRejected
        
        case errSecSelfCheckFailed:
            return .errSecSelfCheckFailed
        
        case errSecServiceNotAvailable:
            return .errSecServiceNotAvailable
        
        case errSecStagedOperationInProgress:
            return .errSecStagedOperationInProgress
        
        case errSecStagedOperationNotStarted:
            return .errSecStagedOperationNotStarted
        
        case errSecTagNotFound:
            return .errSecTagNotFound
        
        case errSecTrustNotAvailable:
            return .errSecTrustNotAvailable
        
        case errSecUnknownFormat:
            return .errSecUnknownFormat
        
        case errSecUnknownTag:
            return .errSecUnknownTag
        
        case errSecUnsupportedAddressType:
            return .errSecUnsupportedAddressType
        
        case errSecUnsupportedFieldFormat:
            return .errSecUnsupportedFieldFormat
        
        case errSecUnsupportedFormat:
            return .errSecUnsupportedFormat
        
        case errSecUnsupportedIndexInfo:
            return .errSecUnsupportedIndexInfo
        
        case errSecUnsupportedLocality:
            return .errSecUnsupportedLocality
        
        case errSecUnsupportedNumAttributes:
            return .errSecUnsupportedNumAttributes
        
        case errSecUnsupportedNumIndexes:
            return .errSecUnsupportedNumIndexes
        
        case errSecUnsupportedNumRecordTypes:
            return .errSecUnsupportedNumRecordTypes
        
        case errSecUnsupportedNumSelectionPreds:
            return .errSecUnsupportedNumSelectionPreds
        
        case errSecUnsupportedOperator:
            return .errSecUnsupportedOperator
        
        case errSecUnsupportedQueryLimits:
            return .errSecUnsupportedQueryLimits
        
        case errSecUnsupportedService:
            return .errSecUnsupportedService
        
        case errSecUnsupportedVectorOfBuffers:
            return .errSecUnsupportedVectorOfBuffers
        
        case errSecVerificationFailure:
            return .errSecVerificationFailure
        
        case errSecVerifyActionFailed:
            return .errSecVerifyActionFailed
        
        case errSecVerifyFailed:
            return .errSecVerifyFailed
            
        default:
            return .unknown(statusCode: self)
        }
    }
}
