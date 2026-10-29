import { randomUUID } from 'crypto';
import { pg } from '../lib/db';

export interface UserRecord {
  id: string;
  tenantId: string;
  email: string;
  displayName: string;
  locale: string;
  timezone: string;
  signature: string;
  role: 'admin' | 'agent' | 'viewer';
  passwordHash: string;
  mfaSecret: string | null;
}

export type PublicUser = Pick<UserRecord, 'id' | 'email' | 'displayName' | 'locale' | 'role'>;

function Audited(): MethodDecorator {
  return (_target, key, descriptor: PropertyDescriptor) => {
    const original = descriptor.value;
    descriptor.value = async function (this: unknown, ...args: unknown[]) {
      const started = Date.now();
      try {
        return await original.apply(this, args);
      } finally {
        await pg.query('INSERT INTO audit_log (action, duration_ms) VALUES ($1, $2)', [String(key), Date.now() - started]);
      }
    };
  };
}

export class UserService {
  defaults(): Partial<UserRecord> {
    return { locale: 'en-GB', timezone: 'UTC', role: 'viewer', signature: '' };
  }

  async findById(id: string): Promise<UserRecord> {
    const { rows } = await pg.query<UserRecord>('SELECT * FROM users WHERE id = $1', [id]);
    if (!rows[0]) throw Object.assign(new Error('user not found'), { status: 404 });
    return rows[0];
  }

  @Audited()
  async save(user: UserRecord): Promise<void> {
    await pg.query('UPDATE users SET email=$2, display_name=$3, locale=$4, timezone=$5, role=$6 WHERE id=$1', [
      user.id, user.email, user.displayName, user.locale, user.timezone, user.role,
    ]);
  }

  @Audited()
  async create(data: Partial<UserRecord>): Promise<UserRecord> {
    const user = { ...this.defaults(), ...data, id: randomUUID() } as UserRecord;
    await pg.query('INSERT INTO users (id, tenant_id, email, role) VALUES ($1, $2, $3, $4)', [user.id, user.tenantId, user.email, user.role]);
    return user;
  }

  @Audited()
  async deleteAccount(id: string): Promise<void> {
    await pg.query('DELETE FROM users WHERE id = $1', [id]);
  }

  @Audited()
  async unlock(id: string): Promise<void> {
    await pg.query('UPDATE users SET locked_until = NULL WHERE id = $1', [id]);
  }

  toPublic(u: UserRecord): PublicUser {
    return { id: u.id, email: u.email, displayName: u.displayName, locale: u.locale, role: u.role };
  }
}

export const userService = new UserService();
