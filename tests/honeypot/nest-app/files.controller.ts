import { Controller, Get, Param, Query, Res } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Response } from 'express';

// honeypot seeds: TAINT-003 (path traversal via @Param into join/readFile)
// + TAINT-005 (reflected XSS: @Query interpolated into server-rendered HTML).
@Controller('files')
export class FilesController {
  @Get(':name')
  read(@Param('name') name: string) {
    return readFileSync(join('/srv/uploads', name));
  }

  @Get('render')
  render(@Query('q') q: string, @Res() res: Response) {
    return res.send(`<h1>search: ${q}</h1>`);
  }
}
