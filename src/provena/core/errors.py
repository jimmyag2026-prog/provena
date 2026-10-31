"""Exception hierarchy. Every verification failure is a VerificationError."""


class ProvenaError(Exception):
    pass


class CanonicalizationError(ProvenaError):
    pass


class VerificationError(ProvenaError):
    pass


class DecryptionError(VerificationError):
    pass
