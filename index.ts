import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import cors from 'cors';
import { PrismaClient } from '@prisma/client'

// -------------------------------------------------

dotenv.config();

// -------------------------------------------------

const prisma = new PrismaClient()
const app = express();

// -------------------------------------------------

app.use(express.json());

// This is ok on Heroku:
app.set('trust proxy', ['uniquelocal']);

const corsOptions = {
  origin: ['https://mail.google.com'],
}

const corsMiddleware = cors(corsOptions);

// -------------------------------------------------

app.get('/ping', (req: Request, res: Response) => {
  res.status(200).send('');
});

app.get('/image.gif', async (req: Request, res: Response) => {
  const {trackId} = req.query;

  // TODO: handle the trackId of other types
  if(trackId){
    await prisma.view.create({data: {
      trackId: String(trackId),
      clientIp: req.ip,
      userAgent: req.headers["user-agent"] ?? '',
    }});
    res.sendFile(path.join(__dirname, '../responses', 'transparent.gif'));
  } else {
    res.status(400).send();
  }
});

app.get('/info', corsMiddleware, async (req: Request, res: Response) => {
  const {threadId} = req.query;
  // TODO: type
  if(threadId){
    const tracker = await prisma.tracker.findFirst({where:{threadId: String(threadId)}, include:{views: true}})
    if(!tracker) {
      res.status(400).send(JSON.stringify({}));
      return;
    }

    const views = tracker.views;

    res.send(JSON.stringify({views}));
  } else {
    res.status(400).send(JSON.stringify({}));
  }
});

app.get('/dashboard', async (req: Request, res: Response) => {
  const views = await prisma.view.findMany();
  const trackers = await prisma.tracker.findMany();

  console.log("views", views);
  console.log("trackers", trackers);

  res.send(JSON.stringify({views, trackers}));
});

app.options('/report', corsMiddleware);
app.post('/report', corsMiddleware, async (req: Request, res: Response) => {
  const {trackId} = req.body;
  const userId = 1;
  if(trackId){
    await prisma.tracker.create({data: {
      userId,
      trackId,
      threadId: req.body.threadId,
      emailId: req.body.emailId,
    }});
    res.send(JSON.stringify({}));
  } else {
    res.status(400).send(JSON.stringify({}));
  }
});

app.get('/login', async (req: Request, res: Response) => {
  res.send("Logging in...");
});

app.get('/logged-in', async (req: Request, res: Response) => {
  res.send("You are logged in. You may close this window.");
});

app.options('/login/magic', corsMiddleware);
app.post('/login/magic', corsMiddleware, async (req: Request, res: Response) => {
  const {email} = req.body;
  if(!email){
    res.status(400).send(JSON.stringify({}));
    return;
  }
  const user = await prisma.user.findFirst({where: {email}});
  if(!user){
    res.status(400).send(JSON.stringify({}));
    return;
  }
  console.log(`https://${req.hostname}/login#accessToken=asdf&expiresIn=3`)

  res.send(JSON.stringify({}));
});

// -------------------------------------------------

if (!process.env.PORT){ throw new Error("Missing PORT"); }
const port = parseInt(process.env.PORT, 10);

app.listen(port, async () => {
  console.log(`[server]: Server is running on ${port}`);
});
