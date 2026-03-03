namespace Titanis.Net.Ldap.Protocol;

/// <summary>
/// LDAP result codes per RFC 4511 Section 4.1.9.
/// </summary>
public enum LdapResultCode
{
    /// <summary>
    /// The operation completed successfully.
    /// </summary>
    Success = 0,

    /// <summary>
    /// An error occurred during the operation.
    /// </summary>
    OperationsError = 1,

    /// <summary>
    /// A protocol error occurred.
    /// </summary>
    ProtocolError = 2,

    /// <summary>
    /// The time limit was exceeded.
    /// </summary>
    TimeLimitExceeded = 3,

    /// <summary>
    /// The size limit was exceeded.
    /// </summary>
    SizeLimitExceeded = 4,

    /// <summary>
    /// The compare operation returned false.
    /// </summary>
    CompareFalse = 5,

    /// <summary>
    /// The compare operation returned true.
    /// </summary>
    CompareTrue = 6,

    /// <summary>
    /// The authentication method is not supported.
    /// </summary>
    AuthMethodNotSupported = 7,

    /// <summary>
    /// Stronger authentication is required.
    /// </summary>
    StrongerAuthRequired = 8,

    /// <summary>
    /// A referral was returned.
    /// </summary>
    Referral = 10,

    /// <summary>
    /// The administrative limit was exceeded.
    /// </summary>
    AdminLimitExceeded = 11,

    /// <summary>
    /// An unavailable critical extension was requested.
    /// </summary>
    UnavailableCriticalExtension = 12,

    /// <summary>
    /// Confidentiality is required.
    /// </summary>
    ConfidentialityRequired = 13,

    /// <summary>
    /// SASL bind is in progress.
    /// </summary>
    SaslBindInProgress = 14,

    /// <summary>
    /// The specified attribute does not exist.
    /// </summary>
    NoSuchAttribute = 16,

    /// <summary>
    /// An undefined attribute type was specified.
    /// </summary>
    UndefinedAttributeType = 17,

    /// <summary>
    /// Inappropriate matching was attempted.
    /// </summary>
    InappropriateMatching = 18,

    /// <summary>
    /// A constraint was violated.
    /// </summary>
    ConstraintViolation = 19,

    /// <summary>
    /// The attribute or value already exists.
    /// </summary>
    AttributeOrValueExists = 20,

    /// <summary>
    /// Invalid attribute syntax.
    /// </summary>
    InvalidAttributeSyntax = 21,

    /// <summary>
    /// The specified object does not exist.
    /// </summary>
    NoSuchObject = 32,

    /// <summary>
    /// An alias problem occurred.
    /// </summary>
    AliasProblem = 33,

    /// <summary>
    /// Invalid DN syntax.
    /// </summary>
    InvalidDnSyntax = 34,

    /// <summary>
    /// An alias dereferencing problem occurred.
    /// </summary>
    AliasDereferencingProblem = 36,

    /// <summary>
    /// Inappropriate authentication was attempted.
    /// </summary>
    InappropriateAuthentication = 48,

    /// <summary>
    /// Invalid credentials were provided.
    /// </summary>
    InvalidCredentials = 49,

    /// <summary>
    /// Insufficient access rights.
    /// </summary>
    InsufficientAccessRights = 50,

    /// <summary>
    /// The server is busy.
    /// </summary>
    Busy = 51,

    /// <summary>
    /// The server is unavailable.
    /// </summary>
    Unavailable = 52,

    /// <summary>
    /// The server is unwilling to perform the operation.
    /// </summary>
    UnwillingToPerform = 53,

    /// <summary>
    /// A loop was detected.
    /// </summary>
    LoopDetect = 54,

    /// <summary>
    /// A naming violation occurred.
    /// </summary>
    NamingViolation = 64,

    /// <summary>
    /// An object class violation occurred.
    /// </summary>
    ObjectClassViolation = 65,

    /// <summary>
    /// The operation is not allowed on non-leaf entries.
    /// </summary>
    NotAllowedOnNonLeaf = 66,

    /// <summary>
    /// The operation is not allowed on RDN.
    /// </summary>
    NotAllowedOnRdn = 67,

    /// <summary>
    /// The entry already exists.
    /// </summary>
    EntryAlreadyExists = 68,

    /// <summary>
    /// Object class modifications are prohibited.
    /// </summary>
    ObjectClassModsProhibited = 69,

    /// <summary>
    /// Affects multiple DSAs (Directory System Agents).
    /// </summary>
    AffectsMultipleDsas = 71,

    /// <summary>
    /// Other unspecified error.
    /// </summary>
    Other = 80,
}
