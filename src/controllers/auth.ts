import { NextFunction , Request,Response } from "express";
import { primsaClient } from "..";

import {compareSync, hashSync} from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { JWT_SECRET } from "../secrets";


import { BadRequestException } from "../exceptions/bad-request";
import { ErrorCode } from "../exceptions/root";
//import { UnprocessableEntityException } from "../exceptions/validation";
import { SignupSchema } from "../schema/users";
import { NotFoundException } from "../exceptions/not-found";



export const signup=async(req:Request,res:Response,next:NextFunction)=>{
    //res.send("Login works")
    

        SignupSchema.parse(req.body)

        const {email,password,name}=req.body;

    //check whether the user already exists
    let user=await primsaClient.user.findFirst({
        where:{
            email:email
        }
    })
    if(user){
        //throw Error("User already exists");
        throw new BadRequestException("User already exists",ErrorCode.USER_ALREADY_EXISTS);
    }
    user=await primsaClient.user.create({
        data:{
            email:email,
            password:hashSync(password,10),
            name:name
        }
    })
    res.json(user);
  
}

export const login=async(req:Request,res:Response,next:NextFunction)=>{
    //res.send("Login works")
    const {email,password}=req.body;

    //check whether the user already exists
    let user=await primsaClient.user.findFirst({
        where:{
            email:email
        }
    })
    if (!user) {
        throw new NotFoundException("User not found sorry", ErrorCode.USER_NOT_FOUND);
    } else if (!compareSync(password, user.password)) {
        throw new BadRequestException("Wrong password", ErrorCode.INCORRECT_PASSWORD);
    } else {
        const token = jwt.sign({ userID: user.id }, JWT_SECRET);
        res.json({ user, token });
    }

}

export const me = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const userHeader = req.headers['x-user'];

        // Check if the userHeader is defined and is a string
        if (typeof userHeader === 'string') {
            // Parse the JSON string into an object
            const user = JSON.parse(userHeader);
            res.json(user);
        } else {
            // Handle the case where the user header is undefined or an array
            // You can return an appropriate error response or handle it as needed
            throw new Error('User information not found in headers');
        }
    } catch (error) {
        next(error); // Pass the error to the error handling middleware
    }
};

