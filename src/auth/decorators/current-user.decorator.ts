import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserDocument } from '../../users/schemas/user.schema';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): UserDocument | { userId: string } => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);

