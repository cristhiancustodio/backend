
import { PrismaClient } from '@prisma/client'
import { users } from './data/users'
import { paises } from './data/paises'
import { departamentosCostaPeru } from './data/provincias'

const prisma = new PrismaClient()

async function main() {
    try {
        await prisma.usuarios.createMany({ data: users });
        await prisma.pais.deleteMany({});
        await prisma.pais.createMany({ data: paises });
        await prisma.provincia.createMany({ data: departamentosCostaPeru });
    } catch (error) {
        // console.log(error)
    }
}
main()
    .then(async () => {
        await prisma.$disconnect()
    })
    .catch(async (e) => {
        //console.error(e)
        await prisma.$disconnect()
        //process.exit(1)
    })