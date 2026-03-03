import type { AuditAdapter, AuditEntry } from '../types'

export function consoleAdapter(): AuditAdapter {
  return {
    log(entry: AuditEntry): void {
      console.log(
        `[prisma-shield:audit] ${entry.timestamp} ${entry.action.toUpperCase()} ${entry.model} by user:${entry.userId} (${entry.operation}, ${entry.duration}ms, ${entry.resultCount} records)`,
      )
    },
  }
}
