import { PrismaClient } from '@prisma/client'
import { shield, generateKey } from 'prisma-shield'
import { consoleAdapter } from 'prisma-shield/adapters'

const ENCRYPTION_KEY = generateKey()
const BLIND_INDEX_KEY = generateKey()

// Raw client (no shield) for verification
const rawPrisma = new PrismaClient()

// Current context — simulates request context
let currentContext = {
  userId: 'user-1',
  tenantId: 'tenant-A',
  role: 'admin',
}

// Shielded client
const prisma = new PrismaClient().$extends(
  shield({
    encrypt: {
      key: ENCRYPTION_KEY,
      blindIndexKey: BLIND_INDEX_KEY,
      fields: {
        user: ['email', 'ssn'],
      },
    },
    rls: {
      context: () => currentContext,
      policies: {
        user: (ctx) => ({ tenantId: ctx.tenantId as string }),
      },
      bypassRoles: ['superadmin'],
    },
    audit: {
      enabled: true,
      adapter: consoleAdapter(),
      logReads: true,
    },
    mask: {
      rules: {
        user: {
          email: { admin: 'none', support: 'partial', viewer: 'full' },
          ssn: { admin: 'none', support: 'full', viewer: 'full' },
        },
      },
    },
  })
)

async function cleanup() {
  await rawPrisma.user.deleteMany()
}

let passed = 0
let failed = 0

function assert(condition: boolean, name: string, details?: string) {
  if (condition) {
    console.log(`  ✅ ${name}`)
    passed++
  } else {
    console.log(`  ❌ ${name}${details ? ` — ${details}` : ''}`)
    failed++
  }
}

async function testEncryption() {
  console.log('\n🔐 TEST: Encryption')

  // Create — should encrypt
  const user = await prisma.user.create({
    data: { email: 'john@test.com', ssn: '123-45-6789', name: 'John', tenantId: 'tenant-A' },
  })

  console.log('  DEBUG create result:', JSON.stringify({ email: user.email?.substring(0, 30), ssn: user.ssn?.substring(0, 30), ssn_idx: (user as any).ssn_idx?.substring(0, 20) }))
  assert(user.email === 'john@test.com', 'create returns decrypted email', `got: ${user.email}`)
  assert(user.ssn === '123-45-6789', 'create returns decrypted ssn', `got: ${user.ssn}`)
  assert(user.name === 'John', 'name is not encrypted')

  // Verify DB stores ciphertext
  const raw = await rawPrisma.user.findFirst({ where: { id: user.id } })
  assert(raw!.email !== 'john@test.com', 'DB stores encrypted email', `got: ${raw!.email?.substring(0, 20)}...`)
  assert(raw!.email_idx !== null && raw!.email_idx !== '', 'DB has blind index')
  assert(raw!.ssn !== '123-45-6789', 'DB stores encrypted ssn')

  // Read — should decrypt
  const found = await prisma.user.findFirst({ where: { id: user.id } })
  assert(found!.email === 'john@test.com', 'findFirst returns decrypted email')
  assert(found!.ssn === '123-45-6789', 'findFirst returns decrypted ssn')
}

async function testBlindIndexSearch() {
  console.log('\n🔍 TEST: Blind Index Search')

  const found = await prisma.user.findFirst({ where: { email: 'john@test.com' } })
  assert(found !== null, 'finds user by encrypted email via blind index')
  assert(found?.email === 'john@test.com', 'returns decrypted email after search')

  const notFound = await prisma.user.findFirst({ where: { email: 'nobody@test.com' } })
  assert(notFound === null, 'returns null for non-existent email')
}

async function testRLS() {
  console.log('\n🔒 TEST: Row-Level Security')

  // Create users in different tenants (via raw to bypass RLS)
  await rawPrisma.user.create({
    data: { email: 'enc1', email_idx: 'idx1', name: 'Alice', tenantId: 'tenant-B', role: 'user' },
  })

  // Current context is tenant-A
  currentContext = { userId: 'user-1', tenantId: 'tenant-A', role: 'admin' }
  const tenantAUsers = await prisma.user.findMany()
  const hasTenantB = tenantAUsers.some((u: any) => u.tenantId === 'tenant-B')
  assert(!hasTenantB, 'tenant-A cannot see tenant-B users')

  // RLS auto-sets tenantId on create
  const newUser = await prisma.user.create({
    data: { email: 'auto@test.com', ssn: '000-00-0000', name: 'Auto', tenantId: 'will-be-overridden' },
  })
  // RLS policy sets tenantId from context
  const rawNew = await rawPrisma.user.findFirst({ where: { id: newUser.id } })
  assert(rawNew!.tenantId === 'tenant-A', 'RLS auto-sets tenantId from context on create')

  // Superadmin bypasses RLS
  currentContext = { userId: 'admin-1', tenantId: 'tenant-A', role: 'superadmin' }
  const allUsers = await prisma.user.findMany()
  const seesTenantB = allUsers.some((u: any) => u.tenantId === 'tenant-B')
  assert(seesTenantB, 'superadmin bypasses RLS and sees all tenants')
}

async function testMasking() {
  console.log('\n🎭 TEST: Data Masking')

  // Admin — sees everything
  currentContext = { userId: 'user-1', tenantId: 'tenant-A', role: 'admin' }
  const admin = await prisma.user.findFirst({ where: { name: 'John' } })
  assert(admin?.email === 'john@test.com', 'admin sees full email')

  // Support — partial mask
  currentContext = { userId: 'user-2', tenantId: 'tenant-A', role: 'support' }
  const support = await prisma.user.findFirst({ where: { name: 'John' } })
  assert(support?.email === 'j***@test.com', 'support sees partial email', `got: ${support?.email}`)
  assert(support?.ssn === '********', 'support sees fully masked ssn', `got: ${support?.ssn}`)

  // Viewer — full mask
  currentContext = { userId: 'user-3', tenantId: 'tenant-A', role: 'viewer' }
  const viewer = await prisma.user.findFirst({ where: { name: 'John' } })
  assert(viewer?.email === '********', 'viewer sees fully masked email', `got: ${viewer?.email}`)
}

async function testFindMany() {
  console.log('\n📋 TEST: findMany + decrypt')

  currentContext = { userId: 'user-1', tenantId: 'tenant-A', role: 'admin' }
  const users = await prisma.user.findMany()
  assert(users.length > 0, `findMany returns ${users.length} users`)

  const allDecrypted = users.every((u: any) =>
    !u.email?.includes('==') || u.email === 'enc1' // base64 ciphertext contains ==
  )
  assert(allDecrypted, 'all emails are decrypted in findMany')
}

async function testUpdate() {
  console.log('\n✏️ TEST: Update')

  currentContext = { userId: 'user-1', tenantId: 'tenant-A', role: 'admin' }

  const user = await prisma.user.findFirst({ where: { name: 'John' } })
  if (!user) {
    assert(false, 'user John exists for update test')
    return
  }

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: { email: 'john.new@test.com' },
  })
  assert(updated.email === 'john.new@test.com', 'update returns decrypted new email')

  // Verify DB is encrypted
  const raw = await rawPrisma.user.findFirst({ where: { id: user.id } })
  assert(raw!.email !== 'john.new@test.com', 'DB stores encrypted updated email')

  // Search by new email
  const found = await prisma.user.findFirst({ where: { email: 'john.new@test.com' } })
  assert(found !== null, 'blind index search works after update')
}

async function main() {
  console.log('=== Prisma Shield E2E Tests ===')
  console.log(`Keys generated. Starting tests...\n`)

  await cleanup()

  await testEncryption()
  await testBlindIndexSearch()
  await testRLS()
  await testMasking()
  await testFindMany()
  await testUpdate()

  console.log(`\n${'='.repeat(40)}`)
  console.log(`Results: ${passed} passed, ${failed} failed`)
  console.log(`${'='.repeat(40)}`)

  await rawPrisma.$disconnect()
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((e) => {
  console.error('💥 Fatal error:', e)
  process.exit(1)
})
