import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import cors from 'cors';

dotenv.config();

const app: Express = express();

const corsOptions = {
  origin: ['https://mail.google.com'],
}

app.use(express.json());
// This is ok on Heroku:
app.set('trust proxy', ['uniquelocal']);

const port = process.env.PORT;

import { Sequelize, Model, InferAttributes, InferCreationAttributes } from 'sequelize';


const sequelize = new Sequelize('sqlite::memory:');

class Tracker extends Model<InferAttributes<Tracker>, InferCreationAttributes<Tracker>> {
  declare trackId: string
  declare threadId: string
  declare emailId: string
}

class View  extends Model<InferAttributes<View>, InferCreationAttributes<View>> {
  declare trackId: string
  declare clientIp: string
  declare userAgent: string
}

app.get('/ping', (req: Request, res: Response) => {
  res.status(200).send('');
});

app.get('/image.gif', async (req: Request, res: Response) => {
  const {trackId} = req.query;

  // TODO: handle the trackId of other types
  if(trackId){
    await View.create({
      trackId: String(trackId),
      clientIp: req.ip,
      userAgent: req.headers["user-agent"] ?? '',
    });
    res.sendFile(path.join(__dirname, '../responses', 'transparent.gif'));
  } else {
    res.status(400).send();
  }
});


app.listen(port, async () => {
  await sequelize.sync();
  console.log(`[server]: Server is running on ${port}`);
});

const corsMiddleware = cors(corsOptions);

app.get('/info', corsMiddleware, async (req: Request, res: Response) => {
  const {threadId} = req.query;
  // TODO: type
  if(threadId){
    const tracker = await Tracker.findOne({where:{threadId: String(threadId)}})
    if(!tracker) {
      res.status(400).send(JSON.stringify({}));
      return;
    }
    const views = await View.findAll({where:{trackId: tracker.trackId}});

    res.send(JSON.stringify({views}));
  } else {
    res.status(400).send(JSON.stringify({}));
  }
});

app.get('/dashboard', async (req: Request, res: Response) => {
  const views = await View.findAll();
  const trackers = await Tracker.findAll();

  console.log("views", views);
  console.log("trackers", trackers);

  res.send(JSON.stringify({views, trackers}));
});

app.options('/report', corsMiddleware);
app.post('/report', corsMiddleware, async (req: Request, res: Response) => {
  const {trackId} = req.body;
  if(trackId){
    await Tracker.create({
      trackId,
      threadId: req.body.threadId,
      emailId: req.body.emailId,
    });
    res.send(JSON.stringify({}));
  } else {
    res.status(400).send(JSON.stringify({}));
  }
});
