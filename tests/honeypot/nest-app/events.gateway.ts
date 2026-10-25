import { WebSocketGateway, SubscribeMessage, MessageBody } from '@nestjs/websockets';

// honeypot seed: WS-001 — gateway handles client events with no connection
// auth: io.use / handleConnection verification / WsGuard all absent.
@WebSocketGateway({ cors: { origin: '*' } })
export class EventsGateway {
  @SubscribeMessage('presence')
  handlePresence(@MessageBody() body: { room: string }) {
    return { joined: body.room };
  }

  @SubscribeMessage('admin-broadcast')
  handleBroadcast(@MessageBody() body: { message: string }) {
    return { sent: body.message };
  }
}
