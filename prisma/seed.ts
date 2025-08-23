
import { PrismaClient } from '@prisma/client'
import { users } from './data/users'

const prisma = new PrismaClient()

async function main() {
    try {
        await prisma.usuarios.createMany({
            data: users
        })
    } catch (error) {
        // console.log(error)
    }
}
main()
    .then(async () => {
        await prisma.$disconnect()
    })
    .catch(async (e) => {
        // console.error(e)
        await prisma.$disconnect()
        // process.exit(1)
    })