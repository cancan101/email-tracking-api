import { PrismaClient } from "@prisma/client";
const { program } = require("commander");

const prisma = new PrismaClient();

async function addUser(email: string): Promise<void> {
  await prisma.user.create({
    data: {
      email,
    },
  });
}

program
  .argument("<email>", "email address for new User")
  .action((email: string) => {
    console.log(email);
    addUser(email)
      .catch((e) => {
        throw e;
      })
      .finally(async () => {
        await prisma.$disconnect();
      });
  });

program.parse();
