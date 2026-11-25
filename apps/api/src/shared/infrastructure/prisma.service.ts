import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  async onModuleInit() {
    // Only attempt live database connection when DATABASE_CONNECT_ON_INIT is explicitly enabled
    if (process.env.DATABASE_CONNECT_ON_INIT === 'true') {
      try {
        await this.$connect();
      } catch (err) {
        console.warn('Prisma could not connect to Postgres database:', err.message);
      }
    }
  }

  async onModuleDestroy() {
    try {
      await this.$disconnect();
    } catch {}
  }
}
