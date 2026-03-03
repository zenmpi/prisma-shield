import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { parseKey } from './keys'

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16

export function encrypt(plaintext: string, key: string | Buffer): string {
  const keyBuffer = parseKey(key)
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv(ALGORITHM, keyBuffer, iv)

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()

  // Format: base64(IV[12] + AuthTag[16] + Ciphertext[N])
  const combined = Buffer.concat([iv, authTag, encrypted])
  return combined.toString('base64')
}

export function decrypt(ciphertext: string, key: string | Buffer): string {
  const keyBuffer = parseKey(key)
  const combined = Buffer.from(ciphertext, 'base64')

  if (combined.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Invalid ciphertext: too short')
  }

  const iv = combined.subarray(0, IV_LENGTH)
  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH)
  const encrypted = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH)

  const decipher = createDecipheriv(ALGORITHM, keyBuffer, iv)
  decipher.setAuthTag(authTag)

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()])
  return decrypted.toString('utf8')
}
