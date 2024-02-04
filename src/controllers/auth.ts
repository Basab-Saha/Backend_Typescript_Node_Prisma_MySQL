import { NextFunction, Request, Response } from "express";
import { primsaClient } from "..";

import {compareSync, hashSync} from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { JWT_SECRET } from "../secrets";


import { BadRequestException } from "../exceptions/bad-request";
import { ErrorCode } from "../exceptions/root";
import { UnprocessableEntityException } from "../exceptions/validation";
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
        next (new BadRequestException("User already exists",ErrorCode.USER_ALREADY_EXISTS))
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
        next(new NotFoundException("User not found sorry", ErrorCode.USER_NOT_FOUND));
    } else if (!compareSync(password, user.password)) {
        next(new BadRequestException("Wrong password", ErrorCode.INCORRECT_PASSWORD));
    } else {
        const token = jwt.sign({ userID: user.id }, JWT_SECRET);
        res.json({ user, token });
    }

}