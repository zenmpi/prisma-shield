# prisma-shield

Security layer for Prisma ORM — field-level encryption, row-level security, audit logging, and data masking. All through one declarative config, zero changes to your business logic.

## Features

- **Field-Level Encryption** — AES-256-GCM encryption with searchable blind indexes (HMAC-SHA256)
- **Row-Level Security** — Automatic tenant/user isolation via where-clause injection
- **Audit Logging** — Fire-and-forget logging of all database operations
- **Data Masking** — Role-based field masking (full, partial, hash, custom)
- **Key Rotation** — Helper to re-encrypt all data with new keys

## Install

```bash
npm install prisma-shield
```

## Quick Start

```ts
import { PrismaClient } from '@prisma/client'
import { shield } from 'prisma-shield'
import { consoleAdapter } from 'prisma-shield/adapters'

const prisma = new PrismaClient().$extends(
  shield({
    encrypt: {
      key: process.env.ENCRYPTION_KEY!,
      blindIndexKey: process.env.BLIND_INDEX_KEY!,
      fields: {
        user: ['email', 'ssn'],
      },
    },
    rls: {
      context: () => getRequestContext(),
      policies: {
        user: (ctx) => ({ tenantId: ctx.tenantId }),
      },
      bypassRoles: ['superadmin'],
    },
    audit: {
      enabled: true,
      adapter: consoleAdapter(),
    },
    mask: {
      rules: {
        user: {
          email: { admin: 'none', support: 'partial', analyst: 'full' },
          ssn: { admin: 'partial', support: 'full', analyst: 'full' },
        },
      },
    },
  })
)

// Works exactly like normal Prisma — security is transparent
await prisma.user.create({ data: { email: 'john@test.com', ssn: '123-45-6789', name: 'John' } })
const user = await prisma.user.findFirst({ where: { email: 'john@test.com' } }) // blind index search
```

Each module is optional. Use only what you need.

## Generate Keys

```bash
npx prisma-shield generate-keys
```

Output:
```
ENCRYPTION_KEY=base64_encoded_256bit_key
BLIND_INDEX_KEY=base64_encoded_256bit_key
```

## Schema Requirements

For each encrypted field, add a `{field}_idx` column for the blind index:

```prisma
model User {
  id        Int     @id @default(autoincrement())
  email     String  // stores ciphertext
  email_idx String? // blind index for search
  ssn       String
  ssn_idx   String?
  name      String
}
```

## Modules

### Encryption

Encrypts fields on write, decrypts on read. Blind indexes enable exact-match search on encrypted data.

```ts
encrypt: {
  key: process.env.ENCRYPTION_KEY!,        // AES-256 key (base64)
  blindIndexKey: process.env.BLIND_INDEX_KEY!, // HMAC key (base64)
  fields: {
    user: ['email', 'ssn'],
    payment: ['cardNumber'],
  },
}
```

**How it works:**
- Write: encrypts value → AES-256-GCM, generates `{field}_idx` → HMAC-SHA256
- Read: decrypts ciphertext, removes `_idx` fields from response
- Search: `where: { email: 'x' }` → `where: { email_idx: hmac('x') }`

### Row-Level Security

Automatically injects where-clauses based on user context.

```ts
rls: {
  context: () => ({
    userId: getCurrentUserId(),
    tenantId: getCurrentTenantId(),
    role: getCurrentUserRole(),
  }),
  policies: {
    user: (ctx) => ({ tenantId: ctx.tenantId }),
    post: (ctx) => ({ authorId: ctx.userId }),
  },
  bypassRoles: ['superadmin'],
}
```

- Reads/updates/deletes: AND-merges policy filter into `where`
- Creates: auto-sets policy fields (e.g., `tenantId`) from context
- Bypass: roles in `bypassRoles` skip RLS entirely

### Audit Logging

Logs all write operations (and optionally reads) with fire-and-forget semantics.

```ts
import { consoleAdapter } from 'prisma-shield/adapters'

audit: {
  enabled: true,
  adapter: consoleAdapter(),
  logReads: false,     // default: don't log reads
  sanitize: true,      // default: replace encrypted values with [ENCRYPTED]
  include: ['user'],   // only these models (optional)
  exclude: ['session'], // skip these models (optional)
}
```

**Built-in adapters:**
- `consoleAdapter()` — logs to console
- `prismaAdapter(prismaClient)` — writes to `AuditLog` model in your database

**Custom adapter:**
```ts
const myAdapter = {
  log(entry) {
    // entry: { timestamp, action, model, userId, operation, args, resultCount, duration }
  }
}
```

### Data Masking

Role-based field masking applied after decryption.

```ts
mask: {
  rules: {
    user: {
      email: { admin: 'none', support: 'partial', analyst: 'full' },
      phone: { admin: 'none', support: 'partial' },
    },
  },
}
```

**Strategies:**
| Strategy | Example |
|----------|---------|
| `'none'` | `john@test.com` (no masking) |
| `'full'` | `********` |
| `'partial'` | `j***@test.com` / `****4567` / `J***` |
| `'hash'` | `a1b2c3d4` (SHA256 prefix) |
| `(v) => string` | Custom function |

Unknown roles default to `'full'` (secure by default).

## Key Rotation

```ts
import { rotateKeys } from 'prisma-shield'

const users = await rawPrisma.user.findMany() // use non-shielded client

const result = rotateKeys(users, ['email', 'ssn'], {
  oldKey: process.env.OLD_ENCRYPTION_KEY!,
  newKey: process.env.NEW_ENCRYPTION_KEY!,
  oldBlindIndexKey: process.env.OLD_BLIND_INDEX_KEY!,
  newBlindIndexKey: process.env.NEW_BLIND_INDEX_KEY!,
})

for (const { id, data } of result.updates) {
  await rawPrisma.user.update({ where: { id }, data })
}

console.log(`Rotated: ${result.processed}, Failed: ${result.failed}`)
```

## Performance

Benchmarks on 10,000 iterations:

| Operation | Time |
|-----------|------|
| Encrypt (short string) | 0.011ms |
| Decrypt (short string) | 0.006ms |
| Blind index | 0.004ms |
| Full round-trip (2 fields) | 0.044ms |

Target: < 5ms per operation.

## Limitations

- Blind index supports **exact match only** (no `LIKE`, `contains`, range queries)
- RLS does **not** apply to nested `include` relations
- Encryption works with **String fields only**
- `$queryRaw` and `$executeRaw` **bypass the pipeline**
- Masking requires RLS context (needs `rls.context` configured)

## License

MIT
