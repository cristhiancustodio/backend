export type IUser = Pick<User, 'id' | 'name' | 'apellido'>;


export interface ICreateUser {
    name: string;
    apellido: string;
    usuario: string;
    email: string;
    password: string;
}
export interface User {
    id: number;
    name: string;
    apellido: string;
    usuario: string;
    email: string;
    password: string;
    confirmed: boolean;
    user_token?: string;
}