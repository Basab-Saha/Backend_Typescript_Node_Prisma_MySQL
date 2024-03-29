import express , {Express} from 'express';
import { PORT } from './secrets';
import rootRouter from './routes';
import { PrismaClient } from '@prisma/client';
import { errorMiddleware } from './middlewares/errors';

const app:Express=express();

app.use(express.json());


app.use('/api',rootRouter);

//we have to export this  coz we will query the database from the prismaClient
export const primsaClient=new PrismaClient({
    log:['query']
});

app.use(errorMiddleware);

app.listen(PORT,()=>{
    console.log("App working ");
})