import {resolve} from 'node:path';
import dotenv from 'dotenv';

const envPath ={
    development: 'dev.env',
    production: 'prod.env',

}
dotenv.config({path: resolve(`./config/${envPath.development}`)});

export const PORT = process.env.PORT || 5000;
export const DB_URI = process.env.DB_URI;
export const JWT_SECRET = process.env.JWT_SECRET;
export const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
export const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
export const SMTP_HOST = process.env.SMTP_HOST;
export const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
export const SMTP_SECURE = process.env.SMTP_SECURE === "true";
export const SMTP_USER = process.env.SMTP_USER;
export const SMTP_PASS = process.env.SMTP_PASS;
export const MAIL_FROM = process.env.MAIL_FROM || SMTP_USER;
export const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;