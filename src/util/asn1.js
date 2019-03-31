import deepForEach from 'deep-for-each';
import cloneDeep from 'clone-deep';
import { Buffer } from 'buffer';
import { typedArrayToUint8Array, bnToUint8Array } from './binary';
import { EncodeAsn1FailedError, DecodeAsn1FailedError } from './errors';

export const decodeAsn1 = (encodedEntity, Model) => {
    let decodedEntity;

    try {
        decodedEntity = Model.decode(Buffer.from(encodedEntity), 'der');
    } catch (err) {
        throw new DecodeAsn1FailedError(Model.name, { originalError: err });
    }

    const mapValue = (value) => {
        // Convert any typed array, including Node's buffer, to Uint8Array
        if (ArrayBuffer.isView(value)) {
            return typedArrayToUint8Array(value);
        }
        // Big number to array buffer
        if (value && value.toArrayLike) {
            return bnToUint8Array(value);
        }

        return value;
    };

    // Apply conversion to all properties deep within the entity
    deepForEach(decodedEntity, (value, key, subject) => {
        subject[key] = mapValue(value);
    });

    return mapValue(decodedEntity);
};

export const encodeAsn1 = (decodedEntity, Model) => {
    const mapValue = (value) => {
        // Typed array to node buffer
        if (value instanceof Uint8Array) {
            return Buffer.from(value);
        }

        return value;
    };

    // Clone argument because we are going to mutate it
    decodedEntity = cloneDeep(decodedEntity);

    // Apply conversion to all properties deep within the entity
    decodedEntity = mapValue(decodedEntity);
    deepForEach(decodedEntity, (value, key, subject) => {
        subject[key] = mapValue(value);
    });

    let encodedEntity;

    try {
        encodedEntity = Model.encode(decodedEntity, 'der');
    } catch (err) {
        throw new EncodeAsn1FailedError(Model.name, { originalError: err });
    }

    // Convert Node's buffer (a typed a array) to Uint8Array
    return typedArrayToUint8Array(encodedEntity);
};
