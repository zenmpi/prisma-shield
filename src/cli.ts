import { generateKey } from './crypto/keys'

const command = process.argv[2]

if (command === 'generate-keys') {
  const encryptionKey = generateKey()
  const blindIndexKey = generateKey()

  console.log('# Add these to your .env file:')
  console.log(`ENCRYPTION_KEY=${encryptionKey}`)
  console.log(`BLIND_INDEX_KEY=${blindIndexKey}`)
} else {
  console.log('Usage: prisma-shield <command>')
  console.log('')
  console.log('Commands:')
  console.log('  generate-keys  Generate encryption and blind index keys')
  process.exit(1)
}
