import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import { config } from '../config';

export interface QueueMessage<T = unknown> {
  id: string;
  topic: string;
  enqueuedAt: string;
  payload: T;
}

const producer = new Redis(config.redisUrl);

export async function enqueue<T>(topic: string, payload: T): Promise<string> {
  const msg: QueueMessage<T> = { id: randomUUID(), topic, enqueuedAt: new Date().toISOString(), payload };
  await producer.xadd(`caseflow:${topic}`, '*', 'msg', JSON.stringify(msg));
  return msg.id;
}
