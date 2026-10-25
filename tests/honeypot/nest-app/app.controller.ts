// honeypot seed: NEST-001 — mutating endpoints, no @UseGuards, no APP_GUARD anywhere
import { Controller, Get, Post, Body } from "@nestjs/common";

@Controller("admin")
export class AdminController {
  @Get("users")
  listUsers() {
    return [];
  }

  @Post("users")
  createUser(@Body() data: any) {
    return data;
  }

  @Post("users/delete")
  deleteUser(@Body() data: any) {
    return data;
  }
}
