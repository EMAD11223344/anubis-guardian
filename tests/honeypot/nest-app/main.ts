// honeypot seeds: NEST-002 wildcard CORS + NEST-003 no helmet + NEST-004 no throttler
// honeypot seed: SWAGGER-001 — API docs exposed with no production guard
import { NestFactory } from "@nestjs/core";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: "*", credentials: true });
  const document = SwaggerModule.createDocument(app, new DocumentBuilder().setTitle("demo").build());
  SwaggerModule.setup("api-docs", app, document);
  await app.listen(3000);
}
bootstrap();
