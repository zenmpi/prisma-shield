import { describe, it, expect, vi } from 'vitest'
import { handleAudit } from '../src/modules/audit'
import type { AuditConfig, AuditAdapter, ShieldContext } from '../src/types'

function createMockAdapter(): AuditAdapter & { entries: any[]; logFn: ReturnType<typeof vi.fn> } {
  const entries: any[] = []
  const logFn = vi.fn((entry) => {
    entries.push(entry)
  })
  return { log: logFn, entries, logFn }
}

const mockContext: ShieldContext = {
  userId: 'user-1',
  role: 'admin',
  ip: '192.168.1.1',
}

describe('handleAudit', () => {
  it('should log a create operation', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter }

    handleAudit(config, 'User', 'create', { data: { name: 'John' } }, { id: 1 }, 5, mockContext)

    expect(adapter.logFn).toHaveBeenCalledOnce()
    const entry = adapter.entries[0]
    expect(entry.action).toBe('create')
    expect(entry.model).toBe('user')
    expect(entry.userId).toBe('user-1')
    expect(entry.ip).toBe('192.168.1.1')
    expect(entry.operation).toBe('create')
    expect(entry.resultCount).toBe(1)
    expect(entry.duration).toBe(5)
    expect(entry.timestamp).toBeDefined()
  })

  it('should not log when disabled', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: false, adapter }

    handleAudit(config, 'User', 'create', {}, {}, 5, mockContext)
    expect(adapter.logFn).not.toHaveBeenCalled()
  })

  it('should not log reads when logReads is false', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, logReads: false }

    handleAudit(config, 'User', 'findMany', {}, [], 5, mockContext)
    expect(adapter.logFn).not.toHaveBeenCalled()
  })

  it('should log reads when logReads is true', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, logReads: true }

    handleAudit(config, 'User', 'findMany', {}, [{ id: 1 }, { id: 2 }], 5, mockContext)
    expect(adapter.logFn).toHaveBeenCalledOnce()
    expect(adapter.entries[0].resultCount).toBe(2)
  })

  it('should respect include filter', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, include: ['user'] }

    handleAudit(config, 'User', 'create', {}, {}, 5, mockContext)
    handleAudit(config, 'Post', 'create', {}, {}, 5, mockContext)

    expect(adapter.logFn).toHaveBeenCalledOnce()
    expect(adapter.entries[0].model).toBe('user')
  })

  it('should respect exclude filter', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, exclude: ['session'] }

    handleAudit(config, 'User', 'create', {}, {}, 5, mockContext)
    handleAudit(config, 'Session', 'create', {}, {}, 5, mockContext)

    expect(adapter.logFn).toHaveBeenCalledOnce()
    expect(adapter.entries[0].model).toBe('user')
  })

  it('should sanitize encrypted fields in args', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter }

    const args = { data: { email: 'john@test.com', name: 'John' } }
    handleAudit(config, 'User', 'create', args, {}, 5, mockContext, ['email'])

    expect(adapter.entries[0].args.data.email).toBe('[ENCRYPTED]')
    expect(adapter.entries[0].args.data.name).toBe('John')
  })

  it('should sanitize encrypted fields in where clause', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, logReads: true }

    const args = { where: { email: 'john@test.com' } }
    handleAudit(config, 'User', 'findMany', args, [], 5, mockContext, ['email'])

    expect(adapter.entries[0].args.where.email).toBe('[ENCRYPTED]')
  })

  it('should not sanitize when sanitize is false', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter, sanitize: false }

    const args = { data: { email: 'john@test.com' } }
    handleAudit(config, 'User', 'create', args, {}, 5, mockContext, ['email'])

    expect(adapter.entries[0].args.data.email).toBe('john@test.com')
  })

  it('should handle null context gracefully', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter }

    handleAudit(config, 'User', 'create', {}, {}, 5, null)
    expect(adapter.entries[0].userId).toBeNull()
  })

  it('should not crash if adapter throws', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const adapter: AuditAdapter = {
      log: () => {
        throw new Error('adapter failed')
      },
    }
    const config: AuditConfig = { enabled: true, adapter }

    expect(() => handleAudit(config, 'User', 'create', {}, {}, 5, mockContext)).not.toThrow()
    consoleSpy.mockRestore()
  })

  it('should not crash if async adapter rejects', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const adapter: AuditAdapter = {
      log: () => Promise.reject(new Error('async adapter failed')),
    }
    const config: AuditConfig = { enabled: true, adapter }

    expect(() => handleAudit(config, 'User', 'create', {}, {}, 5, mockContext)).not.toThrow()
    consoleSpy.mockRestore()
  })

  it('should count result correctly for different result types', () => {
    const adapter = createMockAdapter()
    const config: AuditConfig = { enabled: true, adapter }

    handleAudit(config, 'User', 'create', {}, null, 5, mockContext)
    handleAudit(config, 'User', 'create', {}, { id: 1 }, 5, mockContext)
    handleAudit(config, 'User', 'deleteMany', {}, { count: 5 }, 5, mockContext)

    expect(adapter.entries[0].resultCount).toBe(0) // null
    expect(adapter.entries[1].resultCount).toBe(1) // single object
    expect(adapter.entries[2].resultCount).toBe(5) // count object
  })
})
