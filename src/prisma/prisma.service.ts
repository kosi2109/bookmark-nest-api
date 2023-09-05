import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
    constructor(private configServvice : ConfigService) {
        super({
            datasources : {
                db : {
                    url: configServvice.get('DATABASE_URL')
                }
            }
        })
    }
}
