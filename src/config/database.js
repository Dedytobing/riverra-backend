const supabase = require("./supabase");

async function findOne(table, filter) {
  let query = supabase.from(table).select("*");

  Object.keys(filter).forEach((key) => {
    query = query.eq(key, filter[key]);
  });

  const { data, error } = await query.single();

  if (error) throw error;

  return data;
}

async function findAll(table, filter = {}) {
  let query = supabase.from(table).select("*");

  Object.keys(filter).forEach((key) => {
    query = query.eq(key, filter[key]);
  });

  const { data, error } = await query;

  if (error) throw error;

  return data;
}

async function insert(table, payload) {
  const { data, error } = await supabase
    .from(table)
    .insert(payload)
    .select()
    .single();

  if (error) throw error;

  return data;
}

async function update(table, filter, payload) {
  let query = supabase.from(table).update(payload);

  Object.keys(filter).forEach((key) => {
    query = query.eq(key, filter[key]);
  });

  const { data, error } = await query.select().single();

  if (error) throw error;

  return data;
}

async function remove(table, filter) {
  let query = supabase.from(table).delete();

  Object.keys(filter).forEach((key) => {
    query = query.eq(key, filter[key]);
  });

  const { error } = await query;

  if (error) throw error;

  return true;
}

module.exports = {
  findOne,
  findAll,
  insert,
  update,
  remove,
};
