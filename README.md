<p align="center">
  <img src=".github/banner.svg" alt="Prisma Shield" width="700" />
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/prisma-shield"><img src="https://img.shields.io/npm/v/prisma-shield?color=6D28D9&label=npm" alt="npm version" /></a>
  <a href="https://github.com/zenmpi/prisma-shield/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/prisma-shield?color=4F46E5" alt="license" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-6D28D9" alt="node version" />
  <img src="https://img.shields.io/badge/prisma-%3E%3D5.0-4F46E5" alt="prisma version" />
</p>

---

One config. Zero changes to your business logic. Drop-in `$extends` and your data is encrypted, isolated, audited, and masked.

```ts
const prisma = new PrismaClient().$extends(shield({ ... }))
```

## Features

| Module | What it does |
|--------|-------------|
| **Encryption** | AES-256-GCM per-field encryption with searchable blind indexes (HMAC-SHA256) |
| **Row-Level Security** | Automatic tenant/user isolation — where-clause injection on every query |
| **Audit Logging** | Fire-and-forget operation logging with pluggable adapters |
| **Data Masking** | Role-based field masking: `admin` sees all, `support` sees partial, `analyst` sees `********` |
| **Key Rotation** | Re-encrypt all data when rotating keys |

Each module is **optional**. Use any combination.

---

## Install

```bash
npm install prisma-shield
```

## Quick Start

**1. Generate keys:**

```bash
npx prisma-shield generate-keys
# ENCRYPTION_KEY=...
# BLIND_INDEX_KEY=...
```

**2. Add `_idx` columns** for each encrypted field:

```prisma
model User {
  id        Int     @id @default(autoincrement())
  email     String  // will store ciphertext
  email_idx String? // blind index for search
  ssn       String
  ssn_idx   String?
  name      String
}
```

**3. Wrap your client:**

```ts
import { PrismaClient } from '@prisma/client'
import { shield } from 'prisma-shield'
import { consoleAdapter } from 'prisma-shield/adapters'

const prisma = new PrismaClient().$extends(
  shield({
    encrypt: {
      key: process.env.ENCRYPTION_KEY!,
      blindIndexKey: process.env.BLIND_INDEX_KEY!,
      fields: { user: ['email', 'ssn'] },
    },
    rls: {
      context: () => getRequestContext(),
      policies: { user: (ctx) => ({ tenantId: ctx.tenantId }) },
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
          ssn:   { admin: 'partial', support: 'full', analyst: 'full' },
        },
      },
    },
  })
)
```

**4. Use Prisma as usual** — security is transparent:

```ts
// Data is encrypted in DB, blind index enables search
await prisma.user.create({
  data: { email: 'john@test.com', ssn: '123-45-6789', name: 'John' },
})

// Search works transparently via blind index
const user = await prisma.user.findFirst({
  where: { email: 'john@test.com' },
})

// Result is decrypted + masked based on role:
// admin:   { email: 'john@test.com', ssn: '***-**-6789' }
// support: { email: 'j***@test.com', ssn: '********' }
// analyst: { email: '********',      ssn: '********' }
```

---

## Modules

### Encryption

AES-256-GCM encryption with random IV per write. HMAC-SHA256 blind indexes for searchable encrypted fields.

```ts
encrypt: {
  key: process.env.ENCRYPTION_KEY!,
  blindIndexKey: process.env.BLIND_INDEX_KEY!,
  fields: {
    user: ['email', 'ssn'],
    payment: ['cardNumber'],
  },
}
```

| Operation | What happens |
|-----------|-------------|
| **Write** | `email` → AES-256-GCM ciphertext, `email_idx` → HMAC-SHA256 |
| **Read** | Ciphertext → decrypted plaintext, `_idx` fields removed |
| **Search** | `where: { email: 'x' }` → `where: { email_idx: hmac('x') }` |

### Row-Level Security

Every query gets a where-clause injected from your policy. Creates auto-set policy fields.

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

- `findMany`, `update`, `delete` → AND-merge policy into `where`
- `create`, `createMany` → auto-set policy fields from context
- `bypassRoles` → skip RLS entirely for these roles

### Audit Logging

Fire-and-forget — never blocks your query, never crashes your app.

```ts
import { consoleAdapter } from 'prisma-shield/adapters'

audit: {
  enabled: true,
  adapter: consoleAdapter(),
  logReads: false,      // default
  sanitize: true,       // encrypted values → [ENCRYPTED]
  include: ['user'],    // optional: only these models
  exclude: ['session'], // optional: skip these models
}
```

**Adapters:** `consoleAdapter()` | `prismaAdapter(client)` | custom `{ log(entry) {} }`

### Data Masking

Role-based masking applied after decryption. Unknown roles get `'full'` mask (secure by default).

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

| Strategy | Output |
|----------|--------|
| `'none'` | `john@test.com` |
| `'full'` | `********` |
| `'partial'` | `j***@test.com` / `****4567` / `***-**-6789` |
| `'hash'` | `a1b2c3d4` (consistent SHA256 prefix) |
| `(v) => string` | Custom function |

---

## Key Rotation

```ts
import { rotateKeys } from 'prisma-shield'

const users = await rawPrisma.user.findMany()

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

---

## Performance

Benchmarks (10,000 iterations, Node.js):

| Operation | Time |
|-----------|------|
| AES encrypt | 0.011ms |
| AES decrypt | 0.006ms |
| Blind index (HMAC) | 0.004ms |
| Full round-trip (2 fields) | **0.044ms** |

> Target: < 5ms per operation. Actual: **0.044ms** (113x under budget).

---

## Limitations

- Blind index: **exact match only** (no `LIKE`, `contains`, range queries)
- RLS: **does not apply** to nested `include` relations
- Encryption: **String fields only**
- `$queryRaw` / `$executeRaw` **bypass the pipeline**
- Masking requires RLS context (`rls.context` must be configured)

## License

[MIT](LICENSE)
