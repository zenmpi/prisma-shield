import type { AuditAdapter, AuditEntry } from '../types'

export function prismaAdapter(prismaClient: any): AuditAdapter {
  return {
    async log(entry: AuditEntry): Promise<void> {
      await prismaClient.auditLog.create({
        data: {
          timestamp: entry.timestamp,
          action: entry.action,
          model: entry.model,
          userId: entry.userId != null ? String(entry.userId) : null,
          ip: entry.ip ?? null,
          operation: entry.operation,
          args: JSON.stringify(entry.args),
          resultCount: entry.resultCount,
          duration: entry.duration,
        },
      })
    },
  }
}
