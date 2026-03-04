import { describe, it, expect } from 'vitest'
import { handleRls, resolveContext } from '../src/modules/rls'
import type { RlsConfig, ShieldContext } from '../src/types'
import { ShieldContextError } from '../src/utils/errors'

const mockContext: ShieldContext = {
  userId: 'user-1',
  tenantId: 'tenant-1',
  role: 'admin',
}

const rlsConfig: RlsConfig = {
  context: () => mockContext,
  policies: {
    user: (ctx) => ({ tenantId: ctx.tenantId }),
    post: (ctx) => ({ authorId: ctx.userId }),
  },
  bypassRoles: ['superadmin'],
}

describe('resolveContext', () => {
  it('should resolve context from sync function', async () => {
    const ctx = await resolveContext(rlsConfig)
    expect(ctx.userId).toBe('user-1')
    expect(ctx.role).toBe('admin')
  })

  it('should resolve context from async function', async () => {
    const asyncConfig: RlsConfig = {
      ...rlsConfig,
      context: async () => mockContext,
    }
    const ctx = await resolveContext(asyncConfig)
    expect(ctx.userId).toBe('user-1')
  })

  it('should throw ShieldContextError when context is missing userId', async () => {
    const badConfig: RlsConfig = {
      ...rlsConfig,
      context: () => ({ role: 'admin' } as any),
    }
    await expect(resolveContext(badConfig)).rejects.toThrow(ShieldContextError)
  })

  it('should throw ShieldContextError when context is missing role', async () => {
    const badConfig: RlsConfig = {
      ...rlsConfig,
      context: () => ({ userId: '1' } as any),
    }
    await expect(resolveContext(badConfig)).rejects.toThrow(ShieldContextError)
  })
})

describe('handleRls', () => {
  it('should add where filter for findMany', async () => {
    const args = { where: { name: 'John' } }
    const result = await handleRls(args, 'User', 'findMany', rlsConfig)

    expect(result.args.where).toEqual({
      AND: [{ name: 'John' }, { tenantId: 'tenant-1' }],
    })
    expect(result.context.userId).toBe('user-1')
  })

  it('should add where filter when no existing where', async () => {
    const args = {}
    const result = await handleRls(args, 'User', 'findMany', rlsConfig)

    expect(result.args.where).toEqual({ tenantId: 'tenant-1' })
  })

  it('should add where filter for update (flat merge for unique ops)', async () => {
    const args = { where: { id: 1 }, data: { name: 'Jane' } }
    const result = await handleRls(args, 'User', 'update', rlsConfig)

    expect(result.args.where).toEqual({
      id: 1,
      tenantId: 'tenant-1',
    })
  })

  it('should add where filter for delete (flat merge for unique ops)', async () => {
    const args = { where: { id: 1 } }
    const result = await handleRls(args, 'User', 'delete', rlsConfig)

    expect(result.args.where).toEqual({
      id: 1,
      tenantId: 'tenant-1',
    })
  })

  it('should auto-set policy fields on create', async () => {
    const args = { data: { name: 'John', email: 'john@test.com' } }
    const result = await handleRls(args, 'User', 'create', rlsConfig)

    expect(result.args.data.tenantId).toBe('tenant-1')
    expect(result.args.data.name).toBe('John')
  })

  it('should enforce policy override on create even if user provides conflicting value', async () => {
    const args = { data: { name: 'John', tenantId: 'attacker-tenant' } }
    const result = await handleRls(args, 'User', 'create', rlsConfig)

    expect(result.args.data.tenantId).toBe('tenant-1')
    expect(result.args.data.name).toBe('John')
  })

  it('should auto-set policy fields on createMany', async () => {
    const args = {
      data: [
        { name: 'Alice' },
        { name: 'Bob' },
      ],
    }
    const result = await handleRls(args, 'User', 'createMany', rlsConfig)

    expect(result.args.data[0].tenantId).toBe('tenant-1')
    expect(result.args.data[1].tenantId).toBe('tenant-1')
  })

  it('should handle upsert — where (flat merge) + create', async () => {
    const args = {
      where: { email: 'john@test.com' },
      create: { email: 'john@test.com', name: 'John' },
      update: { name: 'Johnny' },
    }
    const result = await handleRls(args, 'User', 'upsert', rlsConfig)

    expect(result.args.where).toEqual({
      email: 'john@test.com',
      tenantId: 'tenant-1',
    })
    expect(result.args.create.tenantId).toBe('tenant-1')
  })

  it('should bypass RLS for superadmin role', async () => {
    const superadminConfig: RlsConfig = {
      ...rlsConfig,
      context: () => ({ userId: 'admin-1', role: 'superadmin', tenantId: 'tenant-1' }),
    }

    const args = { where: { name: 'John' } }
    const result = await handleRls(args, 'User', 'findMany', superadminConfig)

    expect(result.args).toEqual(args) // unchanged
  })

  it('should not modify args when model has no policy', async () => {
    const args = { where: { id: 1 } }
    const result = await handleRls(args, 'Comment', 'findMany', rlsConfig)

    expect(result.args).toEqual(args)
  })

  it('should use correct policy per model', async () => {
    const args = { where: {} }
    const userResult = await handleRls(args, 'User', 'findMany', rlsConfig)
    const postResult = await handleRls(args, 'Post', 'findMany', rlsConfig)

    expect(userResult.args.where).toEqual({ tenantId: 'tenant-1' })
    expect(postResult.args.where).toEqual({ authorId: 'user-1' })
  })
})
