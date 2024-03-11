import { config } from 'config';
import { Prisma, PrismaClient } from "@pr";
import { CookieOptions, NextFunction } from "express";
import { createUser } from "../services/user.services";
import { signJwt, verifyJwt } from "../utils/jwt";

const cookiesOptions: CookieOptions = {
  httpOnly: true,
  sameSite: "lax",
};

if (process.env.NODE_ENV === "production") {
  cookiesOptions.secure = true;
}

const accessTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  expires: new Date(
    Date.now() + config.get<number>("accessTokenExpiresIn") * 60 * 1000
  ),
  maxAge: config.get<number>("accessTokenExpiresIn") * 60 * 1000,
};

const refreshTokenCookieOptions: CookieOptions = {
  ...cookiesOptions,
  expires: new Date(
    Date.now() + config.get<number>("refreshTokenExpiresIn") * 60 * 1000
  ),
  maxAge: config.get<number>("refreshTokenExpiresIn") * 60 * 1000,
};

//  logics

export const registerUserHandler = async (
  req: Request<{}, {}, RegisterUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 12);
    const verifycode = crypto.randomBytes(32).toString("hex");
    const verificationCode = crypto
      .createHash("sha256")
      .update(verifycode)
      .digest("hex");

    const user = await createUser({
      name: req.body.name,
      email: req.body.email.toLowerCase(),
      password: hashedPassword,
      verificationCode,
    });
    res.status(201).json({
      status: "success",
      data: {
        user,
      },
    });
  } catch (error: any) {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === "P2002") {
        return res.status(409).json({
          status: "fail",
          message: "Email already exists",
        });
      }
    }
    next(error);
  }
};

// login logic

export const LoginUserHandler = async (
  req: Request<{}, {}, LoginUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = req.body;
    const user = await findUniqueUser(
      { email: emaill.toLowerCase() },
      {
        id: true,
        email: true,
        verified: true,
        password: true,
      }
    );

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return next(new AppError(400, "Invalid credentials"));
    }

    // Sign Tokens

    const { access_token, refresh_token } = await signTokens(user);
    res.cookie("access_token", access_token, accessTokenCookieOptions);
    res.cookie("refresh_token", refresh_token, refreshTokenCookieOptions);
    res.cookie("logged_in", true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    res.status(200).json({
      status: "success",
      access_token,
    });
  } catch (error: any) {
    next(error);
  }
};

// refresh token logic

export const refreshAccessTokenHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const refresh_token = req.cookies.refresh_token;
    const message = "Could not refresh access token";

    if (!refresh_token) {
      return next(new AppError(401, message));
    }

    // validate refresh token

    const decoded = verifyJwt<{ sub: string }>(
      refresh_token,
      "refreshTokenPublicKey"
    );

    if (!decoded) {
      return next(new AppError(401, message));
    }

    // check id user has a valid session
    const session = await redisClient.get(decoded.sub)

    if (!session) {
      return next(new AppError(401, message));
    }
    const user = await findUniqueUser({id:JSON.parse(session).id}) 

    if(!user){
      return next(new AppError(401, message));
    }

    //sign new access token
    const access_token = signJwt({ sub: user.id },'accessTokenPrivateKey',{
        expiresIn:`${config.get<number>('accessTokenExpiresIn')}m`
    });

    // add cookies
    res.cookie("access_token", access_token, accessTokenCookieOptions);
    res.cookie("logged_in", true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    })

    // send response
    res.status(200).json({
        status: 'success',
        access_token
    })
  } catch (error:any) {
    next(error);
  }
};


// logout

function logout(res:Response){
    res.cookie('access_token', '', { maxAge: -1 });
    res.cookie('refresh_token', '', { maxAge: -1 });
    res.cookie('logged_in', '', { maxAge: -1 });
}

export const logoutUserhandler = async (
    req: Request,
    res: Response,
    next: NextFunction
)=>{
    try {
        await redisclient.del(res.locals.user.id);
        logout(res);

        res.status(200).json({
            status: 'success'
        })
    } catch (error:any) {
        next(error);
    }
}