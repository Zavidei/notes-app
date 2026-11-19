import { BadRequestException, Body, Controller, Post, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { createToken } from './auth';
import { DbService } from './db.service';
import * as bcrypt from 'bcryptjs';

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private db: DbService) {}

  @Post('register')
  async register(@Body() body: { username: string; password: string }) {
    if (!body.username || !body.password) {
      throw new BadRequestException('Completează utilizatorul și parola');
    }
    if (typeof body.password !== 'string' || body.password.length < 12) {
      throw new BadRequestException('Parola trebuie să aibă minimum 12 caractere');
    }
    if (/^\s|\s$/.test(body.password)) {
      throw new BadRequestException('Parola nu poate începe sau termina cu spațiu');
    }

    const hash = await bcrypt.hash(body.password, 10);

    try {
      const result = await this.db.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
        [body.username, hash],
      );
      const user = result.rows[0];
      return { token: createToken(user), username: user.username };
    } catch {
      throw new BadRequestException('Utilizatorul există deja');
    }
  }

  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    if (!body.username || !body.password) {
      throw new UnauthorizedException('Utilizator sau parolă greșită');
    }

    const result = await this.db.query(
      'SELECT id, username, password FROM users WHERE username = $1',
      [body.username],
    );
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(body.password, user.password))) {
      throw new UnauthorizedException('Utilizator sau parolă greșită');
    }
    return { token: createToken(user), username: user.username };
  }
}