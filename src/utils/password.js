/**
 * Password Hashing Utilities
 *
 * Uses bcrypt for secure password hashing and verification.
 */

import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;
const BCRYPT_PREFIX = '$2';

/**
 * Check if a string is a bcrypt hash
 * @param {string} str - String to check
 * @returns {boolean} True if the string appears to be a bcrypt hash
 */
export function isHashed(str) {
    if (!str || typeof str !== 'string') return false;
    return str.startsWith(BCRYPT_PREFIX) && str.length >= 59;
}

/**
 * Hash a password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Bcrypt hash
 */
export async function hashPassword(password) {
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
    }
    return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Verify a password against a hash
 * @param {string} password - Plain text password to verify
 * @param {string} hash - Bcrypt hash to compare against
 * @returns {Promise<boolean>} True if password matches
 */
export async function verifyPassword(password, hash) {
    if (!password || !hash) return false;

    // If hash is not actually a bcrypt hash (legacy plain text),
    // fall back to direct comparison for migration
    if (!isHashed(hash)) {
        return password === hash;
    }

    return bcrypt.compare(password, hash);
}

/**
 * Hash password synchronously (for use in config loading)
 * @param {string} password - Plain text password
 * @returns {string} Bcrypt hash
 */
export function hashPasswordSync(password) {
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
    }
    return bcrypt.hashSync(password, SALT_ROUNDS);
}

export default {
    isHashed,
    hashPassword,
    verifyPassword,
    hashPasswordSync
};
