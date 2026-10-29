import Redis from 'ioredis';
import { logger } from './logger';

export interface QueueMessage<T = unknown> {
  id: string;
  topic: string;
  enqueuedAt: string;
  payload: T;
}

type Handler = (msg: QueueMessage<any>) => Promise<void> | void;

const handlers = new Map<string, Handler>();

export function on(topic: string, handler: Handler): void {
  handlers.set(topic, handler);
}

export async function run(redisUrl: string): Promise<never> {
  const redis = new Redis(redisUrl);
  let lastId = '$';
  for (;;) {
    const res = await redis.xread('BLOCK', 5000, 'STREAMS', ...[...handlers.keys()].map((t) => `caseflow:${t}`), ...[...handlers.keys()].map(() => lastId));
    for (const [stream, entries] of res ?? []) {
      for (const [id, fields] of entries) {
        lastId = id;
        const msg = JSON.parse(fields[1]) as QueueMessage;
        try {
          await handlers.get(stream.replace(/^caseflow:/, ''))?.(msg);
        } catch (err) {
          logger.error({ err, id, topic: msg.topic }, 'job failed');
        }
      }
    }
  }
}
