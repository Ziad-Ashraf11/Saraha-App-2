import multer from "multer";
import { mkdir, unlink, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
const badRequestError = (message) => {
  const error = new Error(message);
  error.status = 400;
  return error;
};

const allowedTypes = {
  "image/jpeg": { extension: ".jpg", signature: (buffer) => buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff },
  "image/png": { extension: ".png", signature: (buffer) => buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
  "image/webp": { extension: ".webp", signature: (buffer) => buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP" },
  "image/gif": { extension: ".gif", signature: (buffer) => ["GIF87a", "GIF89a"].includes(buffer.toString("ascii", 0, 6)) },
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter(req, file, callback) {
    if (!allowedTypes[file.mimetype]) {
      return callback(badRequestError("Only JPEG, PNG, WebP, or GIF images are allowed"));
    }
    callback(null, true);
  },
});

export const uploadProfileImage = (req, res, next) => {
  upload.single("image")(req, res, (error) => {
    if (error) return next(error);
    if (!req.file) return next(badRequestError("Upload an image using the 'image' field"));
    const type = allowedTypes[req.file.mimetype];
    if (!type.signature(req.file.buffer)) {
      return next(badRequestError("The uploaded file content does not match an allowed image type"));
    }
    const filename = `${randomUUID()}${type.extension}`;
    const directory = path.resolve("uploads");
    mkdir(directory, { recursive: true })
      .then(() => writeFile(path.join(directory, filename), req.file.buffer, { flag: "wx" }))
      .then(() => {
        req.uploadedImageName = filename;
        req.uploadedImagePath = `/uploads/${filename}`;
        next();
      })
      .catch(async (writeError) => {
        try {
          await unlink(path.join(directory, filename));
        } catch {
          // A failed write may not have created a file.
        }
        next(writeError);
      });
  });
};

export const removeStoredImage = async (filename) => {
  if (!filename || path.basename(filename) !== filename) return;
  try {
    await unlink(path.join(path.resolve("uploads"), filename));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
};
