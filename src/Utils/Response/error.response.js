export const ErrorResponse = ({
    message = "Error",
    status = 400,
    extra = undefined,
}) => {
    const error = new Error(
        typeof message === "string" ? message : message?.message,
    );

    error.status = status;
    error.extra = extra;
    throw error;
};

export const BadRequestException = ({
    Message = "Bad Request Exception",
    extra,
}) => {
    return ErrorResponse({
        message: Message,      
        status: 400,
        extra,
    });
};

export const ConflictException = ({
    Message = "Conflict Exception",
    extra,
}) => {
    return ErrorResponse({
        message: Message,
        status: 409,
        extra,
    });
};

export const NotFoundException = ({
    Message = "Not Found Exception",
    extra,
}) => {
    return ErrorResponse({
        message: Message,
        status: 404,
        extra,
    });
};

export const ForbiddenException = ({
    Message = "Forbidden Exception",
    extra,
}) => {
    return ErrorResponse({
        message: Message,
        status: 403,
        extra,
    });
};

export const UnauthorizedException = ({
    Message = "Unauthorized Exception",
    extra,
}) => {
    return ErrorResponse({
        message: Message,
        status: 401,
        extra,
    });
};

export const glopalErrorHandler = (err, req, res, next) => {
    const status = err.status || (err.code === 11000 ? 409 : err.name === "MulterError" ? (err.code === "LIMIT_FILE_SIZE" ? 413 : 400) : err.name === "ValidationError" || err.name === "CastError" ? 400 : 500);
    const message = err.code === 11000
        ? "A record with this value already exists"
        : err.message || "Internal Server Error";
    const extra = err.extra || undefined;

    return res.status(status).json({
        message,
        ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
        extra,
    });
};