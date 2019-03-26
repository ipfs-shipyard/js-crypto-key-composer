import random from 'node-forge/lib/util';
import { binaryStringToArrayBuffer } from './binary';

const randomBytes = (size) => binaryStringToArrayBuffer(random.getBytesSync(size));

export default randomBytes;
