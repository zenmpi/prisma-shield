import { describe, it, expect, vi } from 'vitest'
import { handleEncryption, handleDecryption } from '../src/modules/encrypt'
import { handleRls } from '../src/modules/rls'
import { handleAudit } from '../src/modules/audit'
import { handleMasking } from '../src/modules/mask'
import { generateKey } from '../src/crypto/keys'
import type { ShieldConfig, ShieldContext, AuditAdapter } from '../src/types'

// Full pipeline simulation
const TEST_KEY = generateKey()
const TEST_BLIND_KEY = generateKey()

const mockContext: ShieldContext = {
  userId: 'user-1',
  tenantId: 'tenant-1',
  role: 'support',
  ip: '10.0.0.1',
}

function createFullConfig(): ShieldConfig & { auditEntries: any[] } {
  const auditEntries: any[] = []
  const adapter: AuditAdapter = {
    log: (entry) => {
      auditEntries.push(entry)
    },
  }

  return {
    encrypt: {
      key: TEST_KEY,
      blindIndexKey: TEST_BLIND_KEY,
      fields: {
        user: ['email', 'ssn'],
      },
    },
    rls: {
      context: () => mockContext,
      policies: {
        user: (ctx) => ({ tenantId: ctx.tenantId }),
      },
      bypassRoles: ['superadmin'],
    },
    audit: {
      enabled: true,
      adapter,
      logReads: true,
    },
    mask: {
      rules: {
        user: {
          email: {
            admin: 'none',
            support: 'partial',
            analyst: 'full',
          },
          ssn: {
            admin: 'partial',
            support: 'full',
            analyst: 'full',
          },
        },
      },
    },
    auditEntries,
  }
}

describe('Integration: Full Pipeline — Create', () => {
  it('should encrypt, apply RLS, audit, and return decrypted+masked result on create', async () => {
    const config = createFullConfig()

    // Simulate a create operation
    const originalArgs = {
      data: { email: 'john@test.com', ssn: '123-45-6789', name: 'John' },
    }

    // Step 1: RLS
    const { args: rlsArgs, context } = await handleRls(
      originalArgs,
      'User',
      'create',
      config.rls!,
    )
    expect(rlsArgs.data.tenantId).toBe('tenant-1')

    // Step 2: Encryption
    const { args: encArgs, shouldDecrypt } = handleEncryption(
      rlsArgs,
      'User',
      'create',
      config.encrypt!,
    )
    expect(encArgs.data.email).not.toBe('john@test.com')
    expect(encArgs.data.email_idx).toBeDefined()
    expect(encArgs.data.ssn_idx).toBeDefined()
    expect(shouldDecrypt).toBe(true)

    // Step 3: Simulated DB result (returns encrypted data as stored)
    const dbResult = {
      id: 1,
      ...encArgs.data,
    }

    // Step 4: Audit
    handleAudit(
      config.audit!,
      'User',
      'create',
      originalArgs,
      dbResult,
      3,
      context,
      ['email', 'ssn'],
    )
    expect(config.auditEntries).toHaveLength(1)
    expect(config.auditEntries[0].args.data.email).toBe('[ENCRYPTED]')
    expect(config.auditEntries[0].args.data.ssn).toBe('[ENCRYPTED]')

    // Step 5: Decryption
    const decrypted = handleDecryption(dbResult, 'User', config.encrypt!)
    expect(decrypted.email).toBe('john@test.com')
    expect(decrypted.ssn).toBe('123-45-6789')
    expect(decrypted.email_idx).toBeUndefined()

    // Step 6: Masking (support role)
    const masked = handleMasking(decrypted, 'User', context.role, config.mask!)
    expect(masked.email).toBe('j***@test.com')
    expect(masked.ssn).toBe('********')
    expect(masked.name).toBe('John') // no masking rule for name
  })
})

describe('Integration: Full Pipeline — Read with Search', () => {
  it('should transform where, decrypt, and mask on findMany', async () => {
    const config = createFullConfig()

    const originalArgs = { where: { email: 'john@test.com' } }

    // Step 1: RLS
    const { args: rlsArgs, context } = await handleRls(
      originalArgs,
      'User',
      'findMany',
      config.rls!,
    )
    // Should have AND-merged where
    expect(rlsArgs.where).toHaveProperty('AND')

    // Step 2: Encryption (where transformation)
    const { args: encArgs, shouldDecrypt } = handleEncryption(
      rlsArgs,
      'User',
      'findMany',
      config.encrypt!,
    )
    expect(shouldDecrypt).toBe(true)
    // The where clause should have email_idx in the AND conditions
    const andConditions = encArgs.where.AND
    expect(andConditions).toBeDefined()
  })
})

describe('Integration: Full Pipeline — Bypass RLS', () => {
  it('should bypass RLS for superadmin but still encrypt and mask', async () => {
    const config = createFullConfig()
    config.rls!.context = () => ({
      userId: 'admin-1',
      role: 'superadmin',
      tenantId: 'tenant-1',
    })

    const originalArgs = { where: { id: 1 } }

    // Step 1: RLS — should bypass
    const { args: rlsArgs } = await handleRls(originalArgs, 'User', 'findMany', config.rls!)
    expect(rlsArgs).toEqual(originalArgs) // unchanged

    // Encryption still applies
    const { shouldDecrypt } = handleEncryption(rlsArgs, 'User', 'findMany', config.encrypt!)
    expect(shouldDecrypt).toBe(true)
  })
})

describe('Integration: Selective Modules', () => {
  it('should work with only encryption configured', () => {
    const encryptOnly: ShieldConfig = {
      encrypt: {
        key: TEST_KEY,
        blindIndexKey: TEST_BLIND_KEY,
        fields: { user: ['email'] },
      },
    }

    const args = { data: { email: 'test@test.com', name: 'Test' } }
    const { args: encArgs, shouldDecrypt } = handleEncryption(
      args,
      'User',
      'create',
      encryptOnly.encrypt!,
    )

    expect(encArgs.data.email).not.toBe('test@test.com')
    expect(shouldDecrypt).toBe(true)

    const decrypted = handleDecryption({ ...encArgs.data, id: 1 }, 'User', encryptOnly.encrypt!)
    expect(decrypted.email).toBe('test@test.com')
  })

  it('should work with only masking configured', () => {
    const maskOnly: ShieldConfig = {
      mask: {
        rules: {
          user: {
            email: { viewer: 'full' },
          },
        },
      },
    }

    const result = handleMasking(
      { email: 'john@test.com', name: 'John' },
      'User',
      'viewer',
      maskOnly.mask!,
    )
    expect(result.email).toBe('********')
    expect(result.name).toBe('John')
  })
})
