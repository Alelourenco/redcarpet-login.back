import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { User } from 'src/user/entities/user.entity';
import { UserPayload } from './models/UserPayload';
import { JwtService } from '@nestjs/jwt';
import { UserToken } from './models/UserToken';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        ) {}

    login(user: User): UserToken {
        // Transforma o user em um JWT
        const payload: UserPayload = {
            sub: user.id,
            email: user.email,
            name: user.name,
        }

        const jwtToken = this.jwtService.sign(payload)

        return{
            access_token: jwtToken
    }
}


    async validateUser(email: string, password: string) {
        const user = await this.userService.findByEmail(email)

        if (user) {
            // checa se a senha informada corresponde a hash que está no banco

            const isPasswordValid = await bcrypt.compare(password, user.password)

            if (isPasswordValid) {
                return {
                    ...user,
                    password: undefined,
                }
            }
        }


        // erro ao encontrar user/senha
        throw new Error('Endereço de e-mail ou senha incorretas.')
    }
}
