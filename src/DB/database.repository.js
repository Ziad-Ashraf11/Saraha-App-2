const buildQuery = (query, { select, options = {} } = {}) => {
  if (select) query.select(select);
  if (options.populate) query.populate(options.populate);
  if (options.sort) query.sort(options.sort);
  if (options.limit !== undefined) query.limit(options.limit);
  if (options.skip !== undefined) query.skip(options.skip);
  if (options.lean) query.lean();
  return query;
};

export const findOne = async ({ model, filter = {}, select, options = {} }) =>
  buildQuery(model.findOne(filter), { select, options }).exec();

export const findById = async ({ model, id, select, options = {} }) =>
  buildQuery(model.findById(id), { select, options }).exec();

export const find = async ({ model, filter = {}, select, options = {} }) =>
  buildQuery(model.find(filter), { select, options }).exec();

export const create = async ({
  model,
  data,
  options = { validateBeforeSave: true },
}) => {
  const document = new model(data);
  await document.save(options);
  return document;
};

export const insertMany = async ({ model, data, options = {} }) =>
  model.insertMany(data, options);

export const updateOne = async ({ model, filter = {}, update, options = {} }) =>
  model.updateOne(filter, update, options).exec();

export const findOneAndUpdate = async ({
  model,
  filter = {},
  update,
  options = {},
}) =>
  model.findOneAndUpdate(filter, update, {
    ...options,
    returnDocument: options.returnDocument ?? "after",
    runValidators: options.runValidators ?? true,
  }).exec();

export const findByIdAndUpdate = async ({ model, id, update, options = {} }) =>
  model.findByIdAndUpdate(id, update, {
    ...options,
    returnDocument: options.returnDocument ?? "after",
    runValidators: options.runValidators ?? true,
  }).exec();

export const deleteOne = async ({ model, filter = {} }) =>
  model.deleteOne(filter).exec();

export const findOneAndDelete = async ({ model, filter = {} }) =>
  model.findOneAndDelete(filter).exec();

export const deleteMany = async ({ model, filter = {} }) =>
  model.deleteMany(filter).exec();