import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Set global API route prefix
  app.setGlobalPrefix('api/v1');

  // Global validation pipe for strict DTO payload enforcement
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Enable CORS
  app.enableCors();

  // Setup OpenAPI / Swagger documentation
  const config = new DocumentBuilder()
    .setTitle('Transformer-WAF SaaS API')
    .setDescription(
      'Multi-tenant Cloud-Native WAF Management Plane API (Modular Monolith + DDD)',
    )
    .setVersion('1.0.0')
    .addTag('Tenants', 'Multi-tenant management bounded context')
    .addTag('Health', 'Operational health check endpoints')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}/api/v1`);
  console.log(`Swagger documentation available at: http://localhost:${port}/api/docs`);
}

bootstrap();
