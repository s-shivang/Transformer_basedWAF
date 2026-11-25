import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set global API route prefix
  app.setGlobalPrefix('api/v1');

  // Parse cookies for HttpOnly authentication tokens
  app.use(cookieParser());

  // Global validation pipe for strict DTO payload enforcement
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Enable CORS with credentials for HttpOnly cookie authentication
  app.enableCors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    credentials: true,
  });

  // Setup OpenAPI / Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('Transformer-WAF SaaS API')
    .setDescription(
      'Multi-tenant Cloud-Native WAF Management Plane API (Modular Monolith + DDD)',
    )
    .setVersion('1.0.0')
    .addTag('Auth & Identity', 'Authentication, session management, and RBAC')
    .addTag('Tenants', 'Multi-tenant management bounded context')
    .addTag('Health', 'Operational health check endpoints')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}/api/v1`);
  console.log(`Swagger documentation available at: http://localhost:${port}/api/docs`);
}

bootstrap();
