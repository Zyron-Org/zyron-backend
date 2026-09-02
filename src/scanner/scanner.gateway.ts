import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: 'scanner',
})
export class ScannerGateway {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(ScannerGateway.name);

  handleConnection(client: Socket) {
    this.logger.log(`Client connected to Scanner WebSocket gateway: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected from Scanner WebSocket gateway: ${client.id}`);
  }

  @SubscribeMessage('subscribe_audit_scan')
  handleSubscribeScan(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { auditId: string },
  ) {
    const room = `audit:${data.auditId}:scan`;
    client.join(room);
    this.logger.log(`Client ${client.id} joined WebSocket room ${room}`);

    client.emit('subscribed', {
      room,
      message: `Subscribed to live scan log stream for audit ${data.auditId}`,
    });
  }

  /**
   * Emit live scan progress event to connected frontend clients
   */
  emitScanProgress(auditId: string, event: {
    passNumber: number;
    totalPasses: number;
    tool: string;
    log: string;
    findingCount: number;
  }) {
    const room = `audit:${auditId}:scan`;
    this.server.to(room).emit('scan_progress', {
      auditId,
      timestamp: new Date().toISOString(),
      ...event,
    });
  }
}
