import CryptoJS from 'crypto-js';

export function hashPassword(password) {
    return CryptoJS.SHA512(password).toString();
}

