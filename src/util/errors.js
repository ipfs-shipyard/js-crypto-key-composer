class BaseError extends Error {
    constructor(message, name, code, props) {
        super(message);
        Error.captureStackTrace(this, this.constructor);
        this.name = name || 'BaseError';

        if (code) {
            this.code = code;
        }

        Object.assign(this, props);
    }
}

export class UnexpectedTypeError extends BaseError {
    constructor(message, props) {
        super(message, 'UnexpectedTypeError', 'UNEXPECTED_TYPE', props);
    }
}

export class InvalidInputKeyError extends BaseError {
    constructor(message, props) {
        super(message, 'InvalidInputKeyError', 'INVALID_INPUT_KEY', props);
    }
}

export class AggregatedInvalidInputKeyError extends BaseError {
    constructor(errors, props) {
        super('No format was able to recognize the input key', 'AggregatedInvalidInputKeyError', 'AGGREGATED_INVALID_INPUT_KEY', { ...props, errors });
    }
}

export class UnsupportedFormatError extends BaseError {
    constructor(format, props) {
        super(`Unsupported format '${format}'`, 'UnsupportedFormatError', 'UNSUPPORTED_FORMAT', props);
    }
}

export class UnsupportedAlgorithmError extends BaseError {
    constructor(message, props) {
        super(message, 'UnsupportedAlgorithmError', 'UNSUPPORTED_ALGORITHM', props);
    }
}

export class InvalidKeyDataError extends BaseError {
    constructor(message, props) {
        super(message, 'InvalidKeyDataError', 'INVALID_KEY_DATA', props);
    }
}

export class MissingPasswordError extends BaseError {
    constructor(message, props) {
        super(message, 'MissingPasswordError', 'MISSING_PASSWORD', props);
    }
}

export class DecryptionFailedError extends BaseError {
    constructor(message, props) {
        super(message, 'DecryptionFailedError', 'DECRYPTION_FAILED', props);
    }
}

export class DecodeAsn1FailedError extends BaseError {
    constructor(modelName, props) {
        super(`Failed to decode ${modelName}`, 'DecodeAsn1FailedError', 'DECODE_ASN1_FAILED', { ...props, modelName });
    }
}

export class EncodeAsn1FailedError extends BaseError {
    constructor(modelName, props) {
        super(`Failed to encode ${modelName}`, 'EncodeAsn1FailedError', 'ENCODE_ASN1_FAILED', props);
    }
}
