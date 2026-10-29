import pino from 'pino';

export const logger = pino({ name: 'caseflow-worker', level: process.env.LOG_LEVEL ?? 'info' });
