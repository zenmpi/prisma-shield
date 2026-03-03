/**
 * Performance benchmark for encryption operations.
 * Run: npx tsx benchmarks/encrypt.bench.ts
 */
import { encrypt, decrypt } from '../src/crypto/aes'
import { generateBlindIndex } from '../src/crypto/hmac'
import { encryptFieldValues, decryptFieldValues, transformWhereClause } from '../src/modules/encrypt'
import { generateKey } from '../src/crypto/keys'

const key = generateKey()
const blindKey = generateKey()
const ITERATIONS = 10_000

function bench(name: string, fn: () => void, iterations = ITERATIONS): void {
  // Warmup
  for (let i = 0; i < 100; i++) fn()

  const start = performance.now()
  for (let i = 0; i < iterations; i++) fn()
  const elapsed = performance.now() - start

  const perOp = elapsed / iterations
  console.log(`${name}: ${perOp.toFixed(3)}ms/op (${iterations} iterations, ${elapsed.toFixed(1)}ms total)`)
}

console.log('=== Prisma Shield — Encryption Benchmarks ===\n')

// Raw crypto operations
bench('AES-256-GCM encrypt (short string)', () => {
  encrypt('john@example.com', key)
})

const encrypted = encrypt('john@example.com', key)
bench('AES-256-GCM decrypt (short string)', () => {
  decrypt(encrypted, key)
})

bench('AES-256-GCM encrypt (long string)', () => {
  encrypt('a'.repeat(1000), key)
})

bench('HMAC-SHA256 blind index', () => {
  generateBlindIndex('john@example.com', blindKey)
})

// Module-level operations
bench('encryptFieldValues (2 fields)', () => {
  encryptFieldValues(
    { email: 'john@example.com', ssn: '123-45-6789', name: 'John' },
    ['email', 'ssn'],
    key,
    blindKey,
    'User',
    'create',
  )
})

const encryptedRecord = encryptFieldValues(
  { email: 'john@example.com', ssn: '123-45-6789', name: 'John' },
  ['email', 'ssn'],
  key,
  blindKey,
  'User',
  'create',
)
bench('decryptFieldValues (2 fields)', () => {
  decryptFieldValues(encryptedRecord, ['email', 'ssn'], key, 'User')
})

bench('transformWhereClause (1 field)', () => {
  transformWhereClause({ email: 'john@example.com' }, ['email'], blindKey)
})

// Full round-trip simulation
bench('Full create round-trip (encrypt 2 fields + blind indexes)', () => {
  const data = { email: 'john@example.com', ssn: '123-45-6789', name: 'John' }
  const enc = encryptFieldValues(data, ['email', 'ssn'], key, blindKey, 'User', 'create')
  decryptFieldValues(enc, ['email', 'ssn'], key, 'User')
})

console.log('\n=== Target: < 5ms per operation ===')
