import { randomBytes } from 'node:crypto'
import { ShieldConfigError } from '../utils/errors'

const KEY_LENGTH = 32 // 256 bits

export function parseKey(input: string | Buffer): Buffer {
  if (Buffer.isBuffer(input)) {
    if (input.length !== KEY_LENGTH) {
      throw new ShieldConfigError(`Key must be ${KEY_LENGTH} bytes, got ${input.length}`)
    }
    return input
  }

  const buffer = Buffer.from(input, 'base64')
  if (buffer.length !== KEY_LENGTH) {
    throw new ShieldConfigError(
      `Key must decode to ${KEY_LENGTH} bytes, got ${buffer.length}. Provide a valid base64-encoded 256-bit key.`,
    )
  }
  return buffer
}

export function generateKey(): string {
  return randomBytes(KEY_LENGTH).toString('base64')
}
