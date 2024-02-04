import { Request, Response, NextFunction } from 'express';
import { UnauthorizedException } from "../exceptions/unauthorized";
import { ErrorCode } from "../exceptions/root";

import * as jwt from 'jsonwebtoken';
import { JWT_SECRET } from "../secrets";
import { primsaClient } from "..";

 const authMiddleware=async(req:Request,res:Response,next:NextFunction)=>{

    //step1) Extract the token from the header(named as authorization) this header will be given at the time of login
    const token = req.headers.authorization!

    //step2) If token is not present then throw an error of unauthorized
    if (!token) {
        next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED))
    }
    try {
        //step3) If token is present , verify that token and extract the payload
        const payload = jwt.verify(token , JWT_SECRET) as any;

        //step4) Get the user from payload and check if the user is present in the database
        const user=await primsaClient.user.findFirst({where:{id:payload.userID}})

        //user na thakle unauthorized error throw korbo
        if(!user){
            next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED))
        }
        // ar jodi user thake tahole req.user e user ta store kore debo ar 
        // next() middleware e call korbo
        else{
            req.headers['x-user'] = JSON.stringify(user);
            next();  
        }
    } catch (error) {
        //jodi token verify na korte pare tahole unauthorized error throw korbo
        next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED))
    }
    
}

export default authMiddleware;