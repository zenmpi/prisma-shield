import { createHmac } from 'node:crypto'
import { parseKey } from './keys'

export function generateBlindIndex(value: string, key: string | Buffer): string {
  const keyBuffer = parseKey(key)
  const normalized = value.toLowerCase().trim()
  return createHmac('sha256', keyBuffer).update(normalized).digest('hex')
}
