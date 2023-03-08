//
//  OSError.swift
//  
//
//  Created by Jeremy Bannister on 3/8/23.
//

///
public enum
    OSError:
        Hashable,
        Error {
    
    ///
    case unknown (statusCode: OSStatus)
    
    /// A function or operation is not implemented.
    case errSecUnimplemented
    
    /// The disk is full.
    case errSecDiskFull
    
    /// I/O error.
    case errSecIO
    
    /// The file is already open with write permission.
    case errSecOpWr
    
    /// One or more parameters passed to the function are not valid.
    case errSecParam
    
    /// Write permissions error.
    case errSecWrPerm
    
    /// Failed to allocate memory.
    case errSecAllocate
    
    /// User canceled the operation.
    case errSecUserCanceled
    
    /// Bad parameter or invalid state for operation.
    case errSecBadReq
    
    // MARK: - Internal Error Result Codes

    /// An internal component experienced an error.
    case errSecInternalComponent
    
    /// An unknown Core Foundation error occurred.
    case errSecCoreFoundationUnknown
    
    /// An internal error occurred.
    case errSecInternalError
    
    // MARK: - Keychain Result Codes

    /// No trust results are available.
    case errSecNotAvailable
    
    /// Read-only error.
    case errSecReadOnly
    
    /// Authorization and/or authentication failed.
    case errSecAuthFailed
    
    /// The keychain does not exist.
    case errSecNoSuchKeychain
    
    /// The keychain is not valid.
    case errSecInvalidKeychain
    
    /// A keychain with the same name already exists.
    case errSecDuplicateKeychain
    
    /// More than one callback of the same name exists.
    case errSecDuplicateCallback
    
    /// The callback is not valid.
    case errSecInvalidCallback
    
    /// The item already exists.
    case errSecDuplicateItem
    
    /// The item cannot be found.
    case errSecItemNotFound
    
    /// The buffer is too small.
    case errSecBufferTooSmall
    
    /// The data is too large for the particular data type.
    case errSecDataTooLarge
    
    /// The attribute does not exist.
    case errSecNoSuchAttr
    
    /// The item reference is invalid.
    case errSecInvalidItemRef
    
    /// The search reference is invalid.
    case errSecInvalidSearchRef
    
    /// The keychain item class does not exist.
    case errSecNoSuchClass
    
    /// A default keychain does not exist.
    case errSecNoDefaultKeychain
    
    /// Interaction with the Security Server is not allowed.
    case errSecInteractionNotAllowed
    
    /// The attribute is read-only.
    case errSecReadOnlyAttr
    
    /// The version is incorrect.
    case errSecWrongSecVersion
    
    /// The key size is not allowed.
    case errSecKeySizeNotAllowed
    
    /// There is no storage module available.
    case errSecNoStorageModule
    
    /// There is no certificate module available.
    case errSecNoCertificateModule
    
    /// There is no policy module available.
    case errSecNoPolicyModule
    
    /// User interaction is required.
    case errSecInteractionRequired
    
    /// The data is not available.
    case errSecDataNotAvailable
    
    /// The data is not modifiable.
    case errSecDataNotModifiable
    
    /// The attempt to create a certificate chain failed.
    case errSecCreateChainFailed
    
    /// The preference domain specified is invalid.
    case errSecInvalidPrefsDomain
    
    /// The user interface cannot be displayed because the system is in a dark wake state.
    case errSecInDarkWake
    
    // MARK: - Certificate Result Codes

    /// There is an unknown critical extension flag.
    case errSecUnknownCriticalExtensionFlag
    
    /// The certificate cannot operate.
    case errSecCertificateCannotOperate
    
    /// An expired certificate was detected.
    case errSecCertificateExpired
    
    /// The certificate is not yet valid.
    case errSecCertificateNotValidYet
    
    /// The certificate was revoked.
    case errSecCertificateRevoked
    
    /// The certificate was suspended.
    case errSecCertificateSuspended
    
    /// The certificate authority is not valid.
    case errSecInvalidCertAuthority
    
    /// An invalid certificate group was detected.
    case errSecInvalidCertificateGroup
    
    /// An invalid certificate reference was detected.
    case errSecInvalidCertificateRef
    
    /// The requested name isn’t allowed for this certificate.
    case errSecCertificateNameNotAllowed
    
    /// The requested policy isn’t allowed for this certificate.
    case errSecCertificatePolicyNotAllowed
    
    /// The validity period in the certificate exceeds the maximum allowed period.
    case errSecCertificateValidityPeriodTooLong
    
    // MARK: - ACL Result Codes

    /// An ACL add operation failed.
    case errSecACLAddFailed
    
    /// An ACL change operation failed.
    case errSecACLChangeFailed
    
    /// An ACL delete operation failed.
    case errSecACLDeleteFailed
    
    /// The access control list is not in standard simple form.
    case errSecACLNotSimple
    
    /// An ACL replace operation failed.
    case errSecACLReplaceFailed
    
    /// Adding an application ACL subject failed.
    case errSecAppleAddAppACLSubject
    
    /// The base access control lists are not valid.
    case errSecInvalidBaseACLs
    
    /// An invalid access control list was detected.
    case errSecInvalidACL
    
    // MARK: - CRL Result Codes

    /// The certificate revocation list has expired.
    case errSecCRLExpired
    
    /// The certificate revocation list is not yet valid.
    case errSecCRLNotValidYet
    
    /// The certificate revocation list was not found.
    case errSecCRLNotFound
    
    /// The certificate revocation list server is down.
    case errSecCRLServerDown
    
    /// The certificate revocation list has a bad uniform resource identifier.
    case errSecCRLBadURI
    
    /// The certificate revocation list is not trusted.
    case errSecCRLNotTrusted
    
    /// An unknown certificate extension was detected.
    case errSecUnknownCertExtension
    
    /// An unknown certificate revocation list extension was detected.
    case errSecUnknownCRLExtension
    
    /// The certificate revocation list policy failed.
    case errSecCRLPolicyFailed
    
    /// The certificate revocation list is already signed.
    case errSecCRLAlreadySigned
    
    /// The issuing distribution point is not valid.
    case errSecIDPFailure
    
    /// The certificate revocation list encoding is not valid.
    case errSecInvalidCRLEncoding
    
    /// The certificate revocation list type is not valid.
    case errSecInvalidCRLType
    
    /// The certificate revocation list is not valid.
    case errSecInvalidCRL
    
    /// An invalid certificate revocation list group was detected.
    case errSecInvalidCRLGroup
    
    /// The certificate revocation list index is not valid.
    case errSecInvalidCRLIndex
    
    /// The certificate revocation list authority is not valid.
    case errSecInvaldCRLAuthority
    
    // MARK: - SMIME Result Codes

    /// An email address mismatch was detected.
    case errSecSMIMEEmailAddressesNotFound
    
    /// The appropriate extended key usage for SMIME is not found.
    case errSecSMIMEBadExtendedKeyUsage
    
    /// The key usage is not compatible with SMIME.
    case errSecSMIMEBadKeyUsage
    
    /// The key usage extension is not marked as critical.
    case errSecSMIMEKeyUsageNotCritical
    
    /// No email address is found in the certificate.
    case errSecSMIMENoEmailAddress
    
    /// The subject alternative name extension is not marked as critical.
    case errSecSMIMESubjAltNameNotCritical
    
    /// The appropriate extended key usage for SSL is not found.
    case errSecSSLBadExtendedKeyUsage
    
    // MARK: - OCSP Result Codes

    /// The online certificate status protocol (OCSP) response is incorrect or cannot be parsed.
    case errSecOCSPBadResponse
    
    /// The online certificate status protocol (OCSP) request is incorrect or cannot be parsed.
    case errSecOCSPBadRequest
    
    /// The online certificate status protocol (OCSP) service is unavailable.
    case errSecOCSPUnavailable
    
    /// The online certificate status protocol (OCSP) server does not recognize this certificate.
    case errSecOCSPStatusUnrecognized
    
    /// An end-of-data was detected.
    case errSecEndOfData
    
    /// An incomplete certificate revocation check occurred.
    case errSecIncompleteCertRevocationCheck
    
    /// A network failure occurred.
    case errSecNetworkFailure
    
    /// The online certificate status protocol (OCSP) response is not trusted to a root or anchor certificate.
    case errSecOCSPNotTrustedToAnchor
    
    /// The record is modified.
    case errSecRecordModified
    
    /// The online certificate status protocol (OCSP) response has an invalid signature.
    case errSecOCSPSignatureError
    
    /// The online certificate status protocol (OCSP) response has no signer.
    case errSecOCSPNoSigner
    
    /// The online certificate status protocol (OCSP) responder detected a malformed request.
    case errSecOCSPResponderMalformedReq
    
    /// The online certificate status protocol (OCSP) responder detected an internal error.
    case errSecOCSPResponderInternalError
    
    /// The online certificate status protocol (OCSP) responder is busy, try again later.
    case errSecOCSPResponderTryLater
    
    /// The online certificate status protocol (OCSP) responder requires a signature.
    case errSecOCSPResponderSignatureRequired
    
    /// The online certificate status protocol (OCSP) responder rejects the request as unauthorized.
    case errSecOCSPResponderUnauthorized
    
    /// The online certificate status protocol (OCSP) response nonce does not match the request.
    case errSecOCSPResponseNonceMismatch
    
    // MARK: - Code Signing Result Codes

    /// Code signing encountered an incorrect certificate chain length.
    case errSecCodeSigningBadCertChainLength
    
    /// Code signing found no basic constraints.
    case errSecCodeSigningNoBasicConstraints
    
    /// Code signing encountered an incorrect path length constraint.
    case errSecCodeSigningBadPathLengthConstraint
    
    /// Code signing found no extended key usage.
    case errSecCodeSigningNoExtendedKeyUsage
    
    /// Code signing indicated use of a development-only certificate.
    case errSecCodeSigningDevelopment
    
    /// Resource signing detects an incorrect certificate chain length.
    case errSecResourceSignBadCertChainLength
    
    /// Resource signing detects an error in the extended key usage.
    case errSecResourceSignBadExtKeyUsage
    
    /// The trust setting for this policy is set to Deny.
    case errSecTrustSettingDeny
    
    /// An invalid certificate subject name was detected.
    case errSecInvalidSubjectName
    
    /// An unknown qualified certificate statement was detected.
    case errSecUnknownQualifiedCertStatement
    
    // MARK: - Mobile Me Result Codes

    /// The MobileMe request will be sent during the next connection.
    case errSecMobileMeRequestQueued
    
    /// The MobileMe request was redirected.
    case errSecMobileMeRequestRedirected
    
    /// A MobileMe server error occurred.
    case errSecMobileMeServerError
    
    /// The MobileMe server is not available.
    case errSecMobileMeServerNotAvailable
    
    /// The MobileMe server reported that the item already exists.
    case errSecMobileMeServerAlreadyExists
    
    /// A MobileMe service error occurred.
    case errSecMobileMeServerServiceErr
    
    /// A MobileMe request is already pending.
    case errSecMobileMeRequestAlreadyPending
    
    /// MobileMe has no request pending.
    case errSecMobileMeNoRequestPending
    
    /// A MobileMe certificate signing request verification failure occurred.
    case errSecMobileMeCSRVerifyFailure
    
    /// MobileMe found a failed consistency check.
    case errSecMobileMeFailedConsistencyCheck
    
    // MARK: - Cryptographic Key Result Codes

    /// The key usage is incorrect.
    case errSecKeyUsageIncorrect
    
    /// The key blob type is incorrect.
    case errSecKeyBlobTypeIncorrect
    
    /// The key header is inconsistent.
    case errSecKeyHeaderInconsistent
    
    /// The key must be wrapped to be exported.
    case errSecKeyIsSensitive
    
    /// The key header format is not supported.
    case errSecUnsupportedKeyFormat
    
    /// The key size is not supported.
    case errSecUnsupportedKeySize
    
    /// The key usage mask is not valid.
    case errSecInvalidKeyUsageMask
    
    /// The key usage mask is not supported.
    case errSecUnsupportedKeyUsageMask
    
    /// The key attribute mask is not valid.
    case errSecInvalidKeyAttributeMask
    
    /// The key attribute mask is not supported.
    case errSecUnsupportedKeyAttributeMask
    
    /// The key label is not valid.
    case errSecInvalidKeyLabel
    
    /// The key label is not supported.
    case errSecUnsupportedKeyLabel
    
    /// The key format is not valid.
    case errSecInvalidKeyFormat
    
    /// The specified database has an invalid key blob.
    case errSecInvalidKeyBlob
    
    /// An invalid key hierarchy was detected.
    case errSecInvalidKeyHierarchy
    
    /// An invalid key was encountered.
    case errSecInvalidKeyRef
    
    /// The key usage is not valid for the specified policy.
    case errSecInvalidKeyUsageForPolicy
    
    // MARK: - Invalid Attribute Result Codes
 
    /// A key attribute is not valid.
    case errSecInvalidAttributeKey
    
    /// An init vector attribute is not valid.
    case errSecInvalidAttributeInitVector
    
    /// A salt attribute is not valid.
    case errSecInvalidAttributeSalt
    
    /// A padding attribute is not valid.
    case errSecInvalidAttributePadding
    
    /// A random number attribute is not valid.
    case errSecInvalidAttributeRandom
    
    /// A seed attribute is not valid.
    case errSecInvalidAttributeSeed
    
    /// A passphrase attribute is not valid.
    case errSecInvalidAttributePassphrase
    
    /// A key length attribute is not valid.
    case errSecInvalidAttributeKeyLength
    
    /// A block size attribute is not valid.
    case errSecInvalidAttributeBlockSize
    
    /// An output size attribute is not valid.
    case errSecInvalidAttributeOutputSize
    
    /// The number of rounds attribute is not valid.
    case errSecInvalidAttributeRounds
    
    /// An algorithm parameters attribute is not valid.
    case errSecInvalidAlgorithmParms
    
    /// A label attribute is not valid.
    case errSecInvalidAttributeLabel
    
    /// A key type attribute is not valid.
    case errSecInvalidAttributeKeyType
    
    /// A mode attribute is not valid.
    case errSecInvalidAttributeMode
    
    /// An effective bits attribute is not valid.
    case errSecInvalidAttributeEffectiveBits
    
    /// A start date attribute is not valid.
    case errSecInvalidAttributeStartDate
    
    /// An end date attribute is not valid.
    case errSecInvalidAttributeEndDate
    
    /// A version attribute is not valid.
    case errSecInvalidAttributeVersion
    
    /// A prime attribute is not valid.
    case errSecInvalidAttributePrime
    
    /// A base attribute is not valid.
    case errSecInvalidAttributeBase
    
    /// A subprime attribute is not valid.
    case errSecInvalidAttributeSubprime
    
    /// An iteration count attribute is not valid.
    case errSecInvalidAttributeIterationCount
    
    /// A database handle attribute is not valid.
    case errSecInvalidAttributeDLDBHandle
    
    /// An access credentials attribute is not valid.
    case errSecInvalidAttributeAccessCredentials
    
    /// A public key format attribute is not valid.
    case errSecInvalidAttributePublicKeyFormat
    
    /// A private key format attribute is not valid.
    case errSecInvalidAttributePrivateKeyFormat
    
    /// A symmetric key format attribute is not valid.
    case errSecInvalidAttributeSymmetricKeyFormat
    
    /// A wrapped key format attribute is not valid.
    case errSecInvalidAttributeWrappedKeyFormat
    
    // MARK: - Missing Attribute Result Codes

    /// A key attribute is missing.
    case errSecMissingAttributeKey
    
    /// An init vector attribute is missing.
    case errSecMissingAttributeInitVector
    
    /// A salt attribute is missing.
    case errSecMissingAttributeSalt
    
    /// A padding attribute is missing.
    case errSecMissingAttributePadding
    
    /// A random number attribute is missing.
    case errSecMissingAttributeRandom
    
    /// A seed attribute is missing.
    case errSecMissingAttributeSeed
    
    /// A passphrase attribute is missing.
    case errSecMissingAttributePassphrase
    
    /// A key length attribute is missing.
    case errSecMissingAttributeKeyLength
    
    /// A block size attribute is missing.
    case errSecMissingAttributeBlockSize
    
    /// An output size attribute is missing.
    case errSecMissingAttributeOutputSize
    
    /// The number of rounds attribute is missing.
    case errSecMissingAttributeRounds
    
    /// An algorithm parameters attribute is missing.
    case errSecMissingAlgorithmParms
    
    /// A label attribute is missing.
    case errSecMissingAttributeLabel
    
    /// A key type attribute is missing.
    case errSecMissingAttributeKeyType
    
    /// A mode attribute is missing.
    case errSecMissingAttributeMode
    
    /// An effective bits attribute is missing.
    case errSecMissingAttributeEffectiveBits
    
    /// A start date attribute is missing.
    case errSecMissingAttributeStartDate
    
    /// An end date attribute is missing.
    case errSecMissingAttributeEndDate
    
    /// A version attribute is missing.
    case errSecMissingAttributeVersion
    
    /// A prime attribute is missing.
    case errSecMissingAttributePrime
    
    /// A base attribute is missing.
    case errSecMissingAttributeBase
    
    /// A subprime attribute is missing.
    case errSecMissingAttributeSubprime
    
    /// An iteration count attribute is missing.
    case errSecMissingAttributeIterationCount
    
    /// A database handle attribute is missing.
    case errSecMissingAttributeDLDBHandle
    
    /// An access credentials attribute is missing.
    case errSecMissingAttributeAccessCredentials
    
    /// A public key format attribute is missing.
    case errSecMissingAttributePublicKeyFormat
    
    /// A private key format attribute is missing.
    case errSecMissingAttributePrivateKeyFormat
    
    /// A symmetric key format attribute is missing.
    case errSecMissingAttributeSymmetricKeyFormat
    
    /// A wrapped key format attribute is missing.
    case errSecMissingAttributeWrappedKeyFormat
    
    // MARK: - Timestamp Result Codes

    /// A timestamp is expected but is not found.
    case errSecTimestampMissing
    
    /// The timestamp is not valid.
    case errSecTimestampInvalid
    
    /// The timestamp is not trusted.
    case errSecTimestampNotTrusted
    
    /// The timestamp service is not available.
    case errSecTimestampServiceNotAvailable
    
    /// Found an unrecognized or unsupported algorithm identifier (AI) in timestamp.
    case errSecTimestampBadAlg
    
    /// The timestamp transaction is not permitted or supported.
    case errSecTimestampBadRequest
    
    /// The timestamp data submitted has the wrong format.
    case errSecTimestampBadDataFormat
    
    /// The time source for the timestamp authority is not available.
    case errSecTimestampTimeNotAvailable
    
    /// The requested policy is not supported by the timestamp authority.
    case errSecTimestampUnacceptedPolicy
    
    /// The requested extension is not supported by the timestamp authority.
    case errSecTimestampUnacceptedExtension
    
    /// The additional information requested is not available.
    case errSecTimestampAddInfoNotAvailable
    
    /// The timestamp request cannot be handled due to a system failure .
    case errSecTimestampSystemFailure
    
    /// A signing time is missing.
    case errSecSigningTimeMissing
    
    /// A timestamp transaction is rejected.
    case errSecTimestampRejection
    
    /// A timestamp transaction is waiting.
    case errSecTimestampWaiting
    
    /// A timestamp authority revocation warning is issued.
    case errSecTimestampRevocationWarning
    
    /// A timestamp authority revocation notification is issued.
    case errSecTimestampRevocationNotification
    
    // MARK: - Other Result Codes

    /// The add-in load operation failed.
    case errSecAddinLoadFailed
    
    /// The add-in unload operation failed.
    case errSecAddinUnloadFailed
    
    /// An algorithm mismatch occurred.
    case errSecAlgorithmMismatch
    
    /// The user is already logged in.
    case errSecAlreadyLoggedIn
    
    /// The specified key has an invalid end date.
    case errSecAppleInvalidKeyEndDate
    
    /// The specified key has an invalid start date.
    case errSecAppleInvalidKeyStartDate
    
    /// The public key is incomplete.
    case errSecApplePublicKeyIncomplete
    
    /// A SSLv2 rollback error has occurred.
    case errSecAppleSSLv2Rollback
    
    /// A signature mismatch has occurred.
    case errSecAppleSignatureMismatch
    
    /// The CSP handle was busy.
    case errSecAttachHandleBusy
    
    /// An attribute was not in the context.
    case errSecAttributeNotInContext
    
    /// A block size mismatch occurred.
    case errSecBlockSizeMismatch
    
    /// A callback failed.
    case errSecCallbackFailed
    
    /// A conversion error has occurred.
    case errSecConversionError
    
    /// The database is locked.
    case errSecDatabaseLocked
    
    /// The data store is open.
    case errSecDatastoreIsOpen
    
    /// Unable to decode the provided data.
    case errSecDecode
    
    /// A device error was encountered.
    case errSecDeviceError
    
    /// A device failure has occurred.
    case errSecDeviceFailed
    
    /// A device reset has occurred.
    case errSecDeviceReset
    
    /// A device verification failure has occurred.
    case errSecDeviceVerifyFailed
    
    /// The elective module manager load failed.
    case errSecEMMLoadFailed
    
    /// The elective module manager unload has failed.
    case errSecEMMUnloadFailed
    
    /// An event notification callback was not found.
    case errSecEventNotificationCallbackNotFound
    
    /// The extended key usage extension was not marked critical.
    case errSecExtendedKeyUsageNotCritical
    
    /// Too many fields were specified.
    case errSecFieldSpecifiedMultiple
    
    /// The file is too big.
    case errSecFileTooBig
    
    /// A function has failed.
    case errSecFunctionFailed
    
    /// A function address is not within the verified module.
    case errSecFunctionIntegrityFail
    
    /// A host name mismatch has occurred.
    case errSecHostNameMismatch
    
    /// The specified database has an incompatible blob.
    case errSecIncompatibleDatabaseBlob
    
    /// The field format is incompatible.
    case errSecIncompatibleFieldFormat
    
    /// The specified database has an incompatible key blob.
    case errSecIncompatibleKeyBlob
    
    /// The version is incompatible.
    case errSecIncompatibleVersion
    
    /// An input length error occurred.
    case errSecInputLengthError
    
    /// The client ID is incorrect.
    case errSecInsufficientClientID
    
    /// Insufficient credentials were detected.
    case errSecInsufficientCredentials
    
    /// Invalid access credentials were detected.
    case errSecInvalidAccessCredentials
    
    /// The access request is invalid.
    case errSecInvalidAccessRequest
    
    /// The action is invalid.
    case errSecInvalidAction
    
    /// An invalid add-in function table was detected.
    case errSecInvalidAddinFunctionTable
    
    /// An invalid algorithm was detected.
    case errSecInvalidAlgorithm
    
    /// The authority is not valid.
    case errSecInvalidAuthority
    
    /// The authority key ID is not valid.
    case errSecInvalidAuthorityKeyID
    
    /// The bundle information is not valid.
    case errSecInvalidBundleInfo
    
    /// An invalid context was detected.
    case errSecInvalidContext
    
    /// An invalid DB list was detected.
    case errSecInvalidDBList
    
    /// The database location is not valid.
    case errSecInvalidDBLocation
    
    /// Invalid data was detected.
    case errSecInvalidData
    
    /// The specified database has an invalid blob.
    case errSecInvalidDatabaseBlob
    
    /// An invalid digest algorithm was detected.
    case errSecInvalidDigestAlgorithm
    
    /// The encoding is not valid.
    case errSecInvalidEncoding
    
    /// The extended key usage is not valid.
    case errSecInvalidExtendedKeyUsage
    
    /// The form type is not valid.
    case errSecInvalidFormType
    
    /// An invalid GUID was detected.
    case errSecInvalidGUID
    
    /// An invalid handle was encountered.
    case errSecInvalidHandle
    
    /// The common security services manager handle does not match with the service type.
    case errSecInvalidHandleUsage
    
    /// The ID is not valid.
    case errSecInvalidID
    
    /// The ID linkage is not valid.
    case errSecInvalidIDLinkage
    
    /// The identifier is not valid.
    case errSecInvalidIdentifier
    
    /// The index is not valid.
    case errSecInvalidIndex
    
    /// The index information is not valid.
    case errSecInvalidIndexInfo
    
    /// The input vector is not valid.
    case errSecInvalidInputVector
    
    /// An invalid login name was detected.
    case errSecInvalidLoginName
    
    /// The modify mode is not valid.
    case errSecInvalidModifyMode
    
    /// An invalid name was detected.
    case errSecInvalidName
    
    /// An invalid network address was detected.
    case errSecInvalidNetworkAddress
    
    /// The new owner is not valid.
    case errSecInvalidNewOwner
    
    /// An invalid number of fields were detected.
    case errSecInvalidNumberOfFields
    
    /// The output vector is not valid.
    case errSecInvalidOutputVector
    
    /// An invalid attempt to change the owner of an item.
    case errSecInvalidOwnerEdit
    
    /// An invalid pointer validation checking policy was detected.
    case errSecInvalidPVC
    
    /// The parsing module is not valid.
    case errSecInvalidParsingModule
    
    /// An invalid passthrough ID was detected.
    case errSecInvalidPassthroughID
    
    /// The password reference is invalid.
    case errSecInvalidPasswordRef
    
    /// An invalid pointer was detected.
    case errSecInvalidPointer
    
    /// The policy identifiers are not valid.
    case errSecInvalidPolicyIdentifiers
    
    /// The specified query is not valid.
    case errSecInvalidQuery
    
    /// The trust policy reason is not valid.
    case errSecInvalidReason
    
    /// An invalid record was detected.
    case errSecInvalidRecord
    
    /// The request inputs are not valid.
    case errSecInvalidRequestInputs
    
    /// The requestor is not valid.
    case errSecInvalidRequestor
    
    /// The response vector is not valid.
    case errSecInvalidResponseVector
    
    /// The root or anchor certificate is not valid.
    case errSecInvalidRoot
    
    /// An invalid sample value was detected.
    case errSecInvalidSampleValue
    
    /// An invalid scope was detected.
    case errSecInvalidScope
    
    /// An invalid service mask was detected.
    case errSecInvalidServiceMask
    
    /// An invalid signature was detected.
    case errSecInvalidSignature
    
    /// The stop-on policy is not valid.
    case errSecInvalidStopOnPolicy
    
    /// An invalid sub-service ID was detected.
    case errSecInvalidSubServiceID
    
    /// The subject key ID is not valid.
    case errSecInvalidSubjectKeyID
    
    /// The time specified is not valid.
    case errSecInvalidTimeString
    
    /// The trust setting is invalid.
    case errSecInvalidTrustSetting
    
    /// The trust settings record is corrupted.
    case errSecInvalidTrustSettings
    
    /// The tuple is not valid.
    case errSecInvalidTuple
    
    /// The tuple credentials are not valid.
    case errSecInvalidTupleCredendtials
    
    /// The tuple group is not valid.
    case errSecInvalidTupleGroup
    
    /// The validity period is not valid.
    case errSecInvalidValidityPeriod
    
    /// An invalid value was detected.
    case errSecInvalidValue
    
    /// A library reference was not found.
    case errSecLibraryReferenceNotFound
    
    /// A module directory service error occurred.
    case errSecMDSError
    
    /// A memory error occurred.
    case errSecMemoryError
    
    /// A required entitlement is missing.
    case errSecMissingEntitlement
    
    /// A required certificate extension is missing.
    case errSecMissingRequiredExtension
    
    /// A missing value was detected.
    case errSecMissingValue
    
    /// A module failed to initialize.
    case errSecModuleManagerInitializeFailed
    
    /// A module was not found.
    case errSecModuleManagerNotFound
    
    /// A module manifest verification failure occurred.
    case errSecModuleManifestVerifyFailed
    
    /// A module was not loaded.
    case errSecModuleNotLoaded
    
    /// An attempt was made to import multiple private keys.
    case errSecMultiplePrivKeys
    
    /// Multiple values are not supported.
    case errSecMultipleValuesUnsupported
    
    /// The specified item has no access control.
    case errSecNoAccessForItem
    
    /// No basic constraints were found.
    case errSecNoBasicConstraints
    
    /// No basic CA constraints were found.
    case errSecNoBasicConstraintsCA
    
    /// No default authority was detected.
    case errSecNoDefaultAuthority
    
    /// No field values were detected.
    case errSecNoFieldValues
    
    /// No trust settings were found.
    case errSecNoTrustSettings
    
    /// A function was called without initializing the common security services manager.
    case errSecNotInitialized
    
    /// You are not logged in.
    case errSecNotLoggedIn
    
    /// The certificate is not signed by its proposed parent.
    case errSecNotSigner
    
    /// The trust policy is not trusted.
    case errSecNotTrusted
    
    /// An output length error was detected.
    case errSecOutputLengthError
    
    /// The PVC is already configured.
    case errSecPVCAlreadyConfigured
    
    /// A reference to the calling module was not found in the list of authorized callers.
    case errSecPVCReferentNotFound
    
    /// A password is required for import or export.
    case errSecPassphraseRequired
    
    /// The path length constraint was exceeded.
    case errSecPathLengthConstraintExceeded
    
    /// MAC verification failed during PKCS12 Import.
    case errSecPkcs12VerifyFailure
    
    /// The specified policy cannot be found.
    case errSecPolicyNotFound
    
    /// The privilege is not granted.
    case errSecPrivilegeNotGranted
    
    /// The privilege is not supported.
    case errSecPrivilegeNotSupported
    
    /// The public key is inconsistent.
    case errSecPublicKeyInconsistent
    
    /// The query size is unknown.
    case errSecQuerySizeUnknown
    
    /// The quota was exceeded.
    case errSecQuotaExceeded
    
    /// The trust policy has a rejected form.
    case errSecRejectedForm
    
    /// The request descriptor is not valid.
    case errSecRequestDescriptor
    
    /// The request is lost.
    case errSecRequestLost
    
    /// The request is rejected.
    case errSecRequestRejected
    
    /// Self-check failed.
    case errSecSelfCheckFailed
    
    /// The required service is not available.
    case errSecServiceNotAvailable
    
    /// A staged operation is in progress.
    case errSecStagedOperationInProgress
    
    /// A staged operation was not started.
    case errSecStagedOperationNotStarted
    
    /// The specified tag is not found.
    case errSecTagNotFound
    
    /// No trust results are available.
    case errSecTrustNotAvailable
    
    /// The item you are trying to import has an unknown format.
    case errSecUnknownFormat
    
    /// An unknown tag was detected.
    case errSecUnknownTag
    
    /// The address type is not supported.
    case errSecUnsupportedAddressType
    
    /// The field format is not supported.
    case errSecUnsupportedFieldFormat
    
    /// The specified import or export format is not supported.
    case errSecUnsupportedFormat
    
    /// The index information is not supported.
    case errSecUnsupportedIndexInfo
    
    /// The locality is not supported.
    case errSecUnsupportedLocality
    
    /// The number of attributes is not supported.
    case errSecUnsupportedNumAttributes
    
    /// The number of indexes is not supported.
    case errSecUnsupportedNumIndexes
    
    /// The number of record types is not supported.
    case errSecUnsupportedNumRecordTypes
    
    /// The number of selection predicates is not supported.
    case errSecUnsupportedNumSelectionPreds
    
    /// The operator is not supported.
    case errSecUnsupportedOperator
    
    /// The query limits are not supported.
    case errSecUnsupportedQueryLimits
    
    /// The service is not supported.
    case errSecUnsupportedService
    
    /// The vector of buffers is not supported.
    case errSecUnsupportedVectorOfBuffers
    
    /// A verification failure occurred.
    case errSecVerificationFailure
    
    /// A verify action failed.
    case errSecVerifyActionFailed
    
    /// A cryptographic verification failure occurred.
    case errSecVerifyFailed
}
