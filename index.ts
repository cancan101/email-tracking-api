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

import { Sequelize, DataTypes } from 'sequelize';

const sequelize = new Sequelize('sqlite::memory:');
const Tracker = sequelize.define('Tracker', {
  trackId: DataTypes.STRING,
});

const View = sequelize.define('View', {
  trackId: DataTypes.STRING,
});

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

app.get('/image.gif', async (req: Request, res: Response) => {
  console.log(JSON.stringify(req.headers));
  console.log(JSON.stringify(req.query));
  console.log(req.ip);

    if(req.query.trackId){
      await View.create({
        trackId: req.query.trackId,
      });
    }

  res.sendFile(path.join(__dirname, '../responses', 'transparent.gif'));
});


app.listen(port, async () => {
  await sequelize.sync();
  console.log(`[server]: Server is running at http://localhost:${port}`);
});

app.get('/info', async (req: Request, res: Response) => {
  const views = await View.findAll();
  const trackers = await Tracker.findAll();

  console.log("views", views);
  console.log("trackers", trackers);

  res.send(JSON.stringify({views, trackers}));
});

const corsMiddleware = cors(corsOptions);
app.options('/report', corsMiddleware);
app.post('/report', corsMiddleware, async (req: Request, res: Response) => {
  console.log("Report", req.body);
  if(req.body.trackId){
    await Tracker.create({
      trackId: req.body.trackId,
    });
  }
  res.send(JSON.stringify({}));
});
