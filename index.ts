import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

const app: Express = express();
const port = process.env.PORT;

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

app.get('/image.gif', (req: Request, res: Response) => {
  console.log(JSON.stringify(req.headers));
  console.log(JSON.stringify(req.query));
  console.log(req.ip);
  res.sendFile(path.join(__dirname, '../responses', 'transparent.gif'))
});


app.listen(port, () => {
  console.log(`[server]: Server is running at http://localhost:${port}`);
});
