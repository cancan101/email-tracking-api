import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

const app: Express = express();
const port = process.env.PORT;

import { Sequelize, DataTypes } from 'sequelize';

const sequelize = new Sequelize('sqlite::memory:');
const Tracker = sequelize.define('Tracker', {
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
      await Tracker.create({
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
  const trackers = await Tracker.findAll();
  console.log(trackers);
  res.send(JSON.stringify(trackers));
});
